import java.net.*;
import java.io.*;
import java.util.*;
import java.util.zip.CRC32;
import java.util.Random;
import java.lang.Object.*;

class Ttftp_Pull_Listener extends Thread{
    //NO packet response codes:                    0                1                     2
    private static final String[] NO_RES = {"Access denied", "File not found", "Invalid window size"};
    private static final String   ABORT_RES = "\nRemote host terminated connection";
    private static final String   DISSALLOW_RES = "Disallowing unsafe transfer with host";
    private static final String   RETRY_RES = "\nExceeded maximum retry timeout, aborting transfer";

    private DatagramPacket request;
    private DatagramSocket socket;
    private int buffersize;
    private int windowsize;
    private int port;
    private InetAddress addr;
    private int portnum;
    private byte[] buffer;
    private boolean verbose;
    private boolean dissallow_unsafe;
    private String filename;

    private long file_checksum;
    private long file_size;

    private List<byte[]> packets;
    private long last_ack = -1;

    private void save_file (boolean filesize, boolean checksum) {
	//construct file - this should give us the filesize
	Ttftp_utils.output(verbose, "\nTransfer completed, constructing file...");
	long fsize = (packets.size() - 1) * (buffersize - 10) - 1 
	    + packets.get(packets.size() - 1).length; //magic numbers give us the file size
	byte[] outputfile = new byte[(int)fsize];
	for(int i = 0; i < packets.size(); i++) {
	    System.arraycopy(packets.get(i), 1, outputfile, i*(buffersize - 10), //these all still
			     packets.get(i).length - 1); //have the 1 byte packetnumber to remove!
	}

	if(filesize && checksum) {//we can compare
	    long cs = Ttftp_utils.getCRC32(outputfile);
	    if((fsize == file_size) &&(cs == file_checksum)) //transfer was perfect!
		Ttftp_utils.output(verbose, "Succesful transfer of file.\n Saving file...");
	    else {
		System.out.println("File checksums did not match, aborting save.");
		return;
	    }
	}
	
	try { //save the file
	    FileOutputStream fos = new FileOutputStream("output_" + (new Random()).nextInt() + "_"
							+ filename);
	    fos.write(outputfile);
	    fos.close();
	    System.out.println("    ...Success!");
	}
	catch (Exception e) { //spit out error
	    System.out.println("     Failiure saving file...: " + e);
	}
    }

    private void print_prog (boolean filesize, int prog, long collisions, 
			     long corrupt, long timer, long order) {
	if(!verbose) //skippable!
	    return;
	if(filesize) {
	    if(prog > 100)                  //this could probably be optimised
		prog = 100;
	    if(prog < 0)
		prog = 0;
	    
	    prog += 1;
	    
	    System.out.print("\r");
	    String bar = " Current Progress:    [";
	    for(int i = 0; i < 20; i++) {
		if(i < prog/5)
		    bar += "█";
		else if (i - 1 < prog/5)
		    bar += "▓";
		else
		    bar += "░";
	    }
	    System.out.print(bar + "]    -    %" + prog + "   -   errors: " + collisions + 
			     "   corrupt/timeout/outoforder [" + corrupt + "/" + timer + "/"
			     + order + "]");
	}
	else
	    System.out.print("\r Current progress:    [" + prog + "/?] packets   -   errors: "
         + collisions+ "   corrupt/timeout/outoforder [" + corrupt + "/" + timer + "/" + order + "]");
    }

    private boolean send_ACK  (long ack_num) {
	if(last_ack == ack_num)
	    return false;

	last_ack = ack_num;
	byte[] ack = {(byte)(ack_num % 256)};
	ack = Ttftp_utils.appendHeader(ack, Ttftp_utils.ACK);//not qualified as a proper ack pack
	try { Ttftp_utils.sendPacket(socket, ack, addr, port);}//we get this further up the line
	catch (Exception e) {System.out.println(e); return false;}//so no need to act on this error

	return true;
    } 

    private void send_ABORT() {
	byte[] abort = {};
	abort = Ttftp_utils.appendHeader(abort, Ttftp_utils.ABORT);
	try { Ttftp_utils.sendPacket(socket, abort, addr, port); }
	catch (Exception e) {} //do nothing - no point to it
    }

    private int update_prog(boolean filesize, int packetnumber) { //give us a number to use in the progress indicator
	if(filesize)
	    return (int)(100 * ((float)(packetnumber * buffersize) / file_size));
	else
	    return packetnumber;
    }

    //deal with actually getting the file from the server
    private void receiver(boolean checksum, boolean filesize, int packetnumber) {
	boolean discontinue = false;
	boolean increment_packetnumber = false;
	int retries = 0;
	int prog = 0;
	buffer = new byte[buffersize];
	boolean js = false;
	long collisions = 0; //might as well count them
	long corruptcol = 0;
	long ordercol = 0;
	long timercol = 0;

	while(!discontinue) {
	    try {
		if(packetnumber - last_ack == windowsize ) //do we send an ack?
		    send_ACK(packetnumber + 1);
		if(increment_packetnumber) {
		    packetnumber++;
		    increment_packetnumber = false;
		}
		
		if(packetnumber % 40 == 0) {
		    prog = update_prog(filesize, packetnumber);
		    print_prog(filesize, prog, collisions, corruptcol, timercol, ordercol);
		}
		request = new DatagramPacket(buffer, buffersize);
		socket.setSoTimeout(100); //set socket timeout to 100ms - probably defined in spec
		socket.receive(request);

		port = request.getPort(); //apparently, these actually vanish when we getData()
		addr = request.getAddress(); //so we need to do this here. It doesn't seem to be
		                             //documented in the spec either.
		//trim packet to appropriate size, then ensure it's valid
		byte[] response = Ttftp_utils.pull_packet(request.getData(), request.getLength());
		if(!Ttftp_utils.validPacket(response)) {//see if checksum matches
		    if(retries >= 10 + windowsize) {
			send_ABORT();
			System.out.println(RETRY_RES);
			return;
		    } //we give up? (loud or silent?)
		    retries++;
		    send_ACK(packetnumber); //checking done on other end
		    collisions++;
		    corruptcol++;
		    continue;
		}
		
		//check what type of packet we have: abort/gift/yes are only candidates
		if(response[0] != Ttftp_utils.GIFT) { /* error or abort, or maybe late YES */
		    if(response[0] == Ttftp_utils.YES) { //size of YES = 16 + 9 -> 25
			file_size = Ttftp_utils.extract_long(response, 9);
			file_checksum = Ttftp_utils.extract_long(response, 17);
			Ttftp_utils.output(verbose, "YES packet received: \n    file size:      " 
					   + file_size + "\n    file checksum:  " + file_checksum);
			filesize = true; //we can deal with these now!
			checksum = true;
		    }
		    else if (response[0] == Ttftp_utils.ABORT ){
			send_ABORT(); 
			System.out.println(ABORT_RES); 
			return; 
		    }
		    else {//we should just silently discard this packet-it might be some other opcode
			continue;
		    }
		} 
		
		//our packet is valid, but does it have the right number?
		int datapacketnumber = Ttftp_utils.fromUByte(response[9]);
		if(datapacketnumber == (packetnumber + 1) % 256) { //this packet fully matches!
		    //we need to check if the length is inequal to the buffer size (final packet)
		    if(buffersize != response.length) {
			send_ACK(packetnumber + 1); //final response - host should know they're done
			discontinue = true;
		    }
		    byte[] output = Ttftp_utils.trimHeader(response);
		    packets.add(output);
		    increment_packetnumber = true;
		    retries = 0;
		}
		else {
		    if(retries >= 10 + windowsize){ //not so silently give up
			send_ABORT();
			System.out.println(RETRY_RES); 
			return;
		    } 
		    collisions++;
		    retries++;
		    ordercol++;
		    send_ACK(packetnumber);
		}
	    
	    } catch (SocketTimeoutException e) {
		if(retries >= 10 + windowsize) {
		    send_ABORT();
		    System.out.println(RETRY_RES);
		    return; } //we give up (loud or silent?)
		retries++;
		send_ACK(packetnumber); //checking done on other end
		collisions++;
		timercol++;
	    }
	    catch (Exception e) {
		System.out.println("err: " + e);
	    }
	}
	save_file(filesize, checksum); //save the file to disk
    }

    private void handle_packet(byte OPCODE, byte[] response) { //GIFT v YES packets: handle case
	//is the packet a YES packet?
	if(OPCODE == Ttftp_utils.YES) { //size of yes = 16 + 9 -> 25
	    file_size = Ttftp_utils.extract_long(response, 9);
	    file_checksum = Ttftp_utils.extract_long(response, 17);
	    Ttftp_utils.output(verbose, "YES packet received: \n    file size:      " + file_size
			       + "\n    file checksum:  " + file_checksum);
	    receiver(true, true,-1);
	}
	else { //do we support these YES-less transfers?
	    if(!dissallow_unsafe) { //no - we don't
		Ttftp_utils.output(verbose, "YES packet missed: \n    file size:      unkown"
			       + "\n    file checksum:  unknown");
		packets.add(Ttftp_utils.trimHeader(response));
		if(response.length != buffersize) {//is this our final packet?
		    send_ACK(0); //the packet is safe anyway - ack to signify we got whole file
		    save_file(false, false);
		}
		else { //we actually have work to do!
		    receiver(false, false, 0);
		}
	    }
	    else { //give an error message
		System.out.println(DISSALLOW_RES);
		send_ABORT();
	    }
	}	
    }

    public  void run() {
	try {
	    request = new DatagramPacket(buffer, buffersize); //get the packet they sent us
	    socket.setSoTimeout(1000); //set timeout to 1 second: they should be able to reply
	    socket.receive(request);
	    addr = request.getAddress();
	    port = request.getPort();
	    //check packet for validity
	    byte[] response = Ttftp_utils.pull_packet(request.getData(), request.getLength());
	    if(Ttftp_utils.validPacket(response)) { //checksums match for this packet
		byte OPcode = response[0];
		if(OPcode == Ttftp_utils.NO)
		    System.out.println(NO_RES[response[9]]); //magic numbers: print server response
		else if(OPcode == Ttftp_utils.ABORT)
		    System.out.println(ABORT_RES);
		else if(OPcode == Ttftp_utils.YES || OPcode == Ttftp_utils.GIFT) 
		    handle_packet(OPcode, response); //we can actually do something!
		else
		    throw new Exception();
	    }
	    else
		throw new Exception();
	} catch (SocketTimeoutException ste) {
	    System.out.println("****    Err: remote host did not respond - aborting transfer");
	} catch (Exception e) {
	    System.out.println("****    Err: cannot get valid response from remote host - aborting");
	}
    }

    public Ttftp_Pull_Listener(DatagramSocket socket, int windowsize, int buffersize,
			       boolean verbose, boolean dissallow_unsafe, String filename) {
	this.socket = socket;
	this.windowsize = windowsize;
	this.buffersize = buffersize;
	this.verbose = verbose;
	this.dissallow_unsafe = dissallow_unsafe;
	this.filename = filename;
	buffer = new byte[buffersize];
	packets = new LinkedList<byte[]>();
    }
}

class PullTTFTP {
    static InetAddress addr;
    static int port;
    static String fname;
    static String password = "";
    static int winsize = 1;
    static boolean verbose = false;
    static int buffersize = 1472; //potential support for variable buffer sizes 
    static boolean dissallow_unsafe = false;

    public static void main(String[] args) {
	if(!getInfo(args)) return;
	byte[] getter_packet = Ttftp_utils.requestGETTER(password, fname, winsize);
	getter_packet = Ttftp_utils.appendHeader(getter_packet, Ttftp_utils.GETTER);
	start_listener(getter_packet);
    }

    static void start_listener (byte[] request) {
	try {
	    int ourport = 40000 + (new Random()).nextInt(20000); //select random port to send from
	    DatagramSocket s = new DatagramSocket(ourport);
	    DatagramPacket out = new DatagramPacket(request, request.length, addr, port);
	    s.send(out);

	    Ttftp_Pull_Listener listener = new Ttftp_Pull_Listener(s, winsize, buffersize, verbose,
								   dissallow_unsafe, fname);
	    listener.run();
	}
	catch (Exception e) { System.out.println("Could not send to remote host"); }
    }
    //this looks kinda ugly: we're just fetching the base items, and checking for extensions
    static boolean getInfo(String args[]) { /*[ip][port][filename] (-options: see below)*/
	try {
	    if(args.length < 3 || args.length > 11)
	    throw new Exception();
	    addr = InetAddress.getByName(args[0]);
	    port = Integer.parseInt(args[1]);
	    fname = args[2];
	    int place = 3;
	    while(place < args.length) {
		if(args[place].equals("-v"))
		    verbose = true;
		else if(args[place].equals("-d"))
		    dissallow_unsafe = true;
		else if (args[place].equals("-p"))
		    password = args[++place];
		else if (args[place].equals("-w"))
		    winsize = Integer.parseInt(args[++place]) % (256*256); //2bytes
		else if (args[place].equals("-b"))
		    buffersize = Integer.parseInt(args[++place]);
		else
		    throw new Exception();
		place++;
	    }
	}
	catch (Exception e) {Ttftp_utils.output(true, usage); return false; }
	return true;
    }
    
    static String usage = 
"Usage: [ip] [port] [filename] (-p -w -s -b -d)\n    -p password\n"
   + "    -w window size\n    -v verbose output\n    -b buffersize\n    -d dissallow unsafe";
}


/*
  TTFTP UTILITIES - SUMMARY - 
    Ttftp_utils.
  long          extract_checksum         (array)
  long          extract_long             (array, offset)
  void          store_long               (array, offset, value)
  long          getCRC32                 (array)
  byte[]        pull_packet              (array, length)
  int           fromUByte                (byte)
  byte[]        appendHeader             (array, OPcode)
  void          output                   (verbose, message)
  byte[]        requestGETTER            (password, filename, windowsize)
  void          sendPacket               (socket, array, address, port)             ^e 
  boolean       validPacket              (byte)
  byte          trimHeader               (array)
*/
class Ttftp_utils {
    public static final byte     GETTER  = 1;
    public static final byte     YES     = 2;
    public static final byte     NO      = 3;
    public static final byte     GIFT    = 4;
    public static final byte     ABORT   = 5;
    public static final byte     ACK     = 6;

    public static long extract_long(byte[] array, int off) {
	long a = array[off+0] & 0xff;
	long b = array[off+1] & 0xff;
	long c = array[off+2] & 0xff;
	long d = array[off+3] & 0xff;
	long e = array[off+4] & 0xff;
	long f = array[off+5] & 0xff;
	long g = array[off+6] & 0xff;
	long h = array[off+7] & 0xff;
	return (a<<56 | b<<48 | c<<40 | d<<32 | e<<24 | f<<16 | g<<8 | h);
    }
    
    public static long extract_checksum(byte[] array) { //gets checksum, stores zero in place
	long a = array[1] & 0xff;
	long b = array[2] & 0xff;
	long c = array[3] & 0xff;
	long d = array[4] & 0xff;
	long e = array[5] & 0xff;
	long f = array[6] & 0xff;
	long g = array[7] & 0xff;
	long h = array[8] & 0xff;

	store_long(array, 1, 0);
	return (a<<56 | b<<48 | c<<40 | d<<32 | e<<24 | f<<16 | g<<8 | h);
    }

    public static void store_long(byte[] array, int off, long val) {
	array[off + 0] = (byte)((val & 0xff00000000000000L) >> 56);
	array[off + 1] = (byte)((val & 0x00ff000000000000L) >> 48);
	array[off + 2] = (byte)((val & 0x0000ff0000000000L) >> 40);
	array[off + 3] = (byte)((val & 0x000000ff00000000L) >> 32);
	array[off + 4] = (byte)((val & 0x00000000ff000000L) >> 24);
	array[off + 5] = (byte)((val & 0x0000000000ff0000L) >> 16);
	array[off + 6] = (byte)((val & 0x000000000000ff00L) >>  8);
	array[off + 7] = (byte)((val & 0x00000000000000ffL));
	return;
    }

    public static long getCRC32(byte[] b) {
	CRC32 crc = new CRC32();
	crc.update(b);
	return crc.getValue();
    }

    //trims tail of byte array, giving array of length len
    public static byte[] pull_packet(byte[] arr, int len) {
	byte[] b_out = new byte[len];
	System.arraycopy(arr, 0, b_out, 0, len);
	return b_out;
    }

    //give unsigned equivalent of signed byte  -1 -> 255, -128 -> 128
    public static int fromUByte(byte b) {
	return (int)b & 0xFF;
    }

    //appends TTFTP a header to the start of a packet
    public static byte[] appendHeader(byte[] b, byte opcode) {
	byte[] header = new byte[9 + b.length];
	header[0] = opcode;
	//we calculate the checksum as if it were zero, so add in the packet
	if(b.length != 0) //will be needed for abort packet, which has no body
	    System.arraycopy(b, 0, header, 9, b.length);
	long crc = getCRC32(header);
	store_long(header, 1, crc);
	
	return header;
    }

    //chooses whether or not to output based on boolean value
    public static void output(boolean verbose, String output) {
	if(verbose)
	    System.out.println(output);
    }

    //requests a getter packet
    public static byte[] requestGETTER(String password, String filename, int windowsize) {
	//   2 bytes    string   1 byte    string   1 byte
	// +---------+----------+-------+----------+-------+
	// | winsize | password |   0   | filename |   0   |
	// +---------+----------+-------+----------+-------+	
	//get the byte arrays we need to store things
	byte[] pw = password.getBytes();
	byte[] fn = filename.getBytes();
	byte[] packet = new byte[4 + fn.length + pw.length];
	
	//add in window size
	packet[0] = (byte) ((windowsize & 0xff00) >> 8);
	packet[1] = (byte) ((windowsize & 0x00ff) >> 0);

	//copy parameters into packet
	System.arraycopy(pw, 0, packet, 2, pw.length);
	System.arraycopy(fn, 0, packet, 3 + pw.length, fn.length);

	return packet;
    }

    public static void sendPacket 
	(DatagramSocket s, byte[] packet, InetAddress addr, int port) throws Exception {
	DatagramPacket parcel = new DatagramPacket(packet, packet.length, addr, port);
	s.send(parcel);
    }

    public static boolean validPacket(byte[] b) {
	long datasum  = extract_checksum(b);
	long checksum = getCRC32(b);
	return datasum == checksum;
    }

    public static byte[] trimHeader(byte[] b) {
	byte[] output = new byte[b.length - 9]; //size of header
	if(output.length == 0)
	    return output; //just to be safe!
	
	System.arraycopy(b, 9, output, 0, output.length);
	return output;
    }
}
