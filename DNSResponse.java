import java.net.InetAddress;

import java.nio.*;



// Lots of the action associated with handling a DNS query is processing 
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.


public class DNSResponse {
    private int index; // What part of the response are we dealing with?
    private int queryID;
    private boolean is_response = false;
    private boolean is_authoritative = false;
    private int response_code = 0;
    private int answer_count = 0;
    private String fqdn = new String();
    private short qtype;
    private short qclass;
    private boolean decoded = false;      // Was this response successfully decoded
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional (alternate) response records

    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

	void dumpResponse() {
	}

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len) {
        decode_query(data);

        if(answer_count > 0){
            index += 2;
            AnswerResource ans = new AnswerResource(data);
        }

	    // Extract list of answers, name server, and additional information response 
	    // records
	}

	public void decode_query(byte[] response){
        ByteBuffer buffer = ByteBuffer.wrap(response);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        // We want a buffer to load data into and extract from

        // Query ID
        queryID = buffer.getShort(index);

        buffer.order(ByteOrder.BIG_ENDIAN); // DO NOT ASK ME WHY I DO NOT KNOW

        // Query response
        index = 2;
        if((buffer.get(index) & 0x80) == 0x80){
            is_response = true;
        }

        // isAuthoritative
        if((buffer.get(index) & 0x04) == 0x04){
            is_authoritative = true;
        }

        // Response code
        index++;
        byte rc = buffer.get(index);
        if((rc &0x03) == 0x03){
            response_code = -1;
        }
        if((rc &0x00) != 0x00){ // ?
            response_code = -4;
        }

        // Answer count
        index = 6;
        answer_count = buffer.getShort(index);

        // NS Count
        index = 8;
        nsCount = buffer.getShort(index);

        // Additional record count
        index = 10;
        additionalCount = buffer.getShort(index);

        // QNAME
        extract_domain(buffer);
        index = 12; // Reset after using in extract_domain (holy shit this is dumb)

        // QTYPE
        index += fqdn.length() + 2; // Length of address + starting label + terminating 0x00
        qtype = buffer.getShort(index);

        // QCLASS
        index +=  2;
        qclass = buffer.getShort(index);
    }

    private void extract_domain(ByteBuffer domain){
        index = 12;
        int label;
        char c;
        int i;

        while(domain.get(index) != 0x00){
            i = 0;
            label = domain.get(index);
            while(i < label){
                i++;
                index++;
                c = (char) domain.get(index);
                fqdn = fqdn.concat(Character.toString(c));
            }
            fqdn = fqdn.concat(".");
            index++;
        }
        fqdn = fqdn.substring(0, fqdn.length() - 1); // Pull the last . off
    }



    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.

    public class AnswerResource {
        private String name = new String();
        private String type = new String(); // ?
        private String data_class = new String(); // ?
        private InetAddress ip;

        public AnswerResource(byte[] data){
            decode_answer(data);
        }

        private void decode_answer(byte[] data){
            ByteBuffer buffer = ByteBuffer.wrap(data);
            System.out.println(index);
            System.out.println(String.format("0x%08x", buffer.get(index)));
            index++;
            System.out.println(buffer.get(index));
            index++;
            System.out.println(buffer.getShort(index));
        }

    }

    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records. 
}


