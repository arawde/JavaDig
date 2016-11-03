
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;

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
        DatagramSocket UDPsocket = new DatagramSocket();

        System.out.println("Encoding query");

		byte[] encoded_query = encode(domain);

		System.out.println("Query encoded!");

		DatagramPacket query =
				new DatagramPacket(encoded_query, encoded_query.length, root, 53);
		UDPsocket.send(query);
        UDPsocket.close();
	}

	private static byte[] encode(String domain){
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		// We tried byte[] and ByteBuffer[], but we want the dynamic memory of this stream

		// Query ID
		Random r = new Random(); // Let's make a query ID
		int id = r.nextInt(32768);
		//String id = Integer.toBinaryString(r.nextInt(8192) + 1); // We don't want an ID of zero
		byte[] query_id = {(byte) (id &0xff), (byte) ((id >>> 8) &0xff)};

		buffer.write(query_id, 0, query_id.length);

		// Flags
		byte flags = (byte) 0x00; // 4.1.1 RFC 1035, we are making a query
		buffer.write(flags);

		// Response code
		byte response_code = (byte) 0x00; // Same as above
		buffer.write(response_code);

		// Query Count
		byte[] qdcount = {(byte) 0x00, (byte) 0x01}; // One query a ah ah
		buffer.write(qdcount, 0, qdcount.length);

		// Answer count
		byte[] ancount = {(byte) 0x00, (byte) 0x00};
		buffer.write(ancount, 0, ancount.length);

		// Name Server Records
		byte[] nscount = {(byte) 0x00, (byte) 0x00};
		buffer.write(nscount, 0, nscount.length);

		// Additional Record Count
		byte[] arcount = {(byte) 0x00, (byte) 0x00};
		buffer.write(arcount, 0, arcount.length);

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

		buffer.write(encodedFQDN, 0, encodedFQDN.length);

		// End of QNAME
		buffer.write((byte) 0x00); // 0 byte indicates end of QNAME

		// QTYPE
		byte[] qtype = {(byte) 0x00, (byte) 0x01};
		buffer.write(qtype, 0, qtype.length);

		// QCLASS
		byte[] qclass = {(byte) 0x00, (byte) 0x01};
		buffer.write(qclass, 0, qclass.length);

		byte[] b = buffer.toByteArray();

		//System.out.println(buffer.toString());
		for(int k = 0; k < b.length; k++){
			System.out.println(String.format("0x%08X", b[k]));
		}

		return buffer.toByteArray();
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


