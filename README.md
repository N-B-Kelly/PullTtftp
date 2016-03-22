# TTFTP-Client
My implementation of the trivial trivial file transfer client as based on the spec agreed upon by the class of C312

To use, there must be a server listening for incoming connections somewhere. The compiled java file should be called with the appropriate parameters, and then magic should happen. The file will be saved as output_[id]_filename on target computer.

The following arguments are expected:
  1. IP - either an IPv4 Address or a hostname
  2. port - port number of the host
  3. filename - filename we want to get

The following arguments are optional:
  *  -p password - surround by "quotes" for more than one word/to include spaces
  *  -w windowsize - window size to request from the host. 
  *  -v  - enable verbose output
  *  -b buffersize - buffersize to use. default is 1472, most host will only support this. merely there for completeness.
  *  -d - dissalow unsafe transfers (i.e - yes header not received)

