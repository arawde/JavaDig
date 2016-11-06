
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

import java.io.ByteArrayOutputStream;
import java.util.Random;

// Exceptions
import java.io.IOException;
import java.net.SocketException;

/**
 * 
 */

/**
 * @author Donald Acton
 * This example is adapted from Kurose & Ross
 *
 */
public class DNSlookup {


	static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
	static boolean tracingOn = false;
	static InetAddress rootNameServer;
    private int attempts;
    static int id;
    static String url = new String();

    /**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		String fqdn;
		DNSResponse response; // Just to force compilation
		int argCount = args.length;
		
		if (argCount < 2 || argCount > 3) {
			usage();
			return;
		}

		rootNameServer = InetAddress.getByName(args[0]);
		fqdn = args[1];
		
		if (argCount == 3 && args[2].equals("-t")) {
			tracingOn = true;
		}
		
		// Start adding code here to initiate the lookup
	    lookup(rootNameServer, fqdn);
	}

	private static void lookup(InetAddress root, String domain) throws SocketException, IOException {
        url = domain;
        DatagramSocket UDPsocket = new DatagramSocket();
		UDPsocket.setSoTimeout(2500); // 5 second timeout exception

		// This will probably have to become a loop

		byte[] encoded_query = encode(domain);
        byte[] response_buffer = new byte[512]; // This might need to be larger

		DatagramPacket query =
				new DatagramPacket(encoded_query, encoded_query.length, root, 53);
        DatagramPacket r = new DatagramPacket(response_buffer, response_buffer.length);


        UDPsocket.send(query);
        trace();
        int timeout = 0;
        while(timeout < 2){
            try{
                UDPsocket.receive(r);
                DNSResponse response = new DNSResponse(r.getData(), r.getData().length);
                break;
            } catch(SocketTimeoutException e){
                timeout++;
                UDPsocket.send(query);
                trace();
            }
        }
        if(timeout >= 2){
            System.out.printf("%s %s %s%n", domain, -2, "0.0.0.0");
        } else {
            if(tracingOn){
                System.out.println("DUMP LIKE EXXON VALDEZE");
            }
        }

		// End
		UDPsocket.close();
	}

	private static byte[] encode(String domain){
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		// We tried byte[] and ByteBuffer[], but we want the dynamic memory of this stream

		// Query ID
		Random r = new Random(); // Let's make a query ID
		id = r.nextInt(32766)+1;

		byte[] query_id = {(byte) (id &0xff), (byte) ((id >>> 8) &0xff)};

		// Flags
		byte flags = (byte) 0x00; // 4.1.1 RFC 1035, we are making a query

		// Response code
		byte response_code = (byte) 0x00; // Same as above

		// Query Count
		byte[] qdcount = {(byte) 0x00, (byte) 0x01}; // One query a ah ah

		// Answer count
		byte[] ancount = {(byte) 0x00, (byte) 0x00};

		// Name Server Records
		byte[] nscount = {(byte) 0x00, (byte) 0x00};

		// Additional Record Count
		byte[] arcount = {(byte) 0x00, (byte) 0x00};

		// QNAME
		byte[] encodedFQDN = new byte[domain.length() + 1];
		String[] fqdnParts = domain.split("[.]");
		int accumulator = 0;
		for(int i = 0; i < fqdnParts.length; i++){
			encodedFQDN[accumulator] = (byte) fqdnParts[i].length();
			for(int j = 0; j< fqdnParts[i].length(); j++) {
				encodedFQDN[++accumulator] = (byte) (fqdnParts[i].charAt(j));
			}
			accumulator++;
		}

		// QTYPE
		byte[] qtype = {(byte) 0x00, (byte) 0x01};

		// QCLASS
		byte[] qclass = {(byte) 0x00, (byte) 0x01};

		// Build our query
		buffer.write(query_id, 0, query_id.length);
		buffer.write(flags);
		buffer.write(response_code);
		buffer.write(qdcount, 0, qdcount.length);
		buffer.write(ancount, 0, ancount.length);
		buffer.write(nscount, 0, nscount.length);
		buffer.write(arcount, 0, arcount.length);
		buffer.write(encodedFQDN, 0, encodedFQDN.length);
		buffer.write((byte) 0x00); // END QNAME
		buffer.write(qtype, 0, qtype.length);
		buffer.write(qclass, 0, qclass.length);

		return buffer.toByteArray();
	}

	private static void trace(){
        if(tracingOn){
            System.out.printf("%n%n%s     %d %s %s %s%n",
                    "Query ID", id, url, "-->", rootNameServer.getHostAddress());
        }
    }

	private static void usage() {
		System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-t]");
		System.out.println("   where");
		System.out.println("       rootDNS - the IP address (in dotted form) of the root");
		System.out.println("                 DNS server you are to start your search at");
		System.out.println("       name    - fully qualified domain name to lookup");
		System.out.println("       -t      -trace the queries made and responses received");
	}
}


