import java.net.InetAddress;
import java.net.UnknownHostException;

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
    private int ns_count = 0;
    private int additional_count = 0;
    private String fqdn = new String();
    private short qtype;
    private short qclass;
    private AnswerResource[] answers;
    private NSResource[] name_servers;
    private boolean decoded = false;      // Was this response successfully decoded

    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

	void dumpResponse() {
	}

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len) {
        decode_query(data);

        index += 2; // We want to increment past the end of the query

        // Extract answers
        //Resource r = new Resource(data);
        if(answer_count > 0){
            answers = new AnswerResource[answer_count];
            for(int i = 0; i < answer_count; i++) {
                answers[i] = new AnswerResource(data);
                answers[i].print_answer();
            }
        }

        // Extract name servers
        if(ns_count > 0){
            name_servers = new NSResource[ns_count];
            for(int i = 0; i < answer_count; i++){
                name_servers[i] = new NSResource(data);
            }
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
        ns_count = buffer.getShort(index);

        // Additional record count
        index = 10;
        additional_count = buffer.getShort(index);

        // QNAME
        index = 12;
        fqdn = extract_domain(buffer, index);

        // QTYPE
        index += fqdn.length() + 2; // Length of address + starting label + terminating 0x00
        qtype = buffer.getShort(index);

        // QCLASS
        index +=  2;
        qclass = buffer.getShort(index);
    }

    private String extract_domain(ByteBuffer data, int offset){
        int label;
        char c;
        int i;
        String top = new String();
        String domain = new String();


        while(data.get(offset) != 0x00){
            i = 0;
            label = data.get(offset);
            if((label & 0xc0) == 0xc0){
                int pointer = (data.getShort(index) & 0x3f);
                System.out.println(pointer);
                top = extract_domain(data, pointer);
            }
            while(i < label){
                i++;
                offset++;
                c = (char) data.get(offset);
                domain = domain.concat(Character.toString(c));
            }
            domain = domain.concat(".");
            domain = domain.concat(top);
            offset++;
        }
        return domain = domain.substring(0, domain.length() - 1); // Pull the last . off
    }



    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.

    public class Resource {
        protected ByteBuffer buffer;
        private String name = new String();
        private int pointer;
        private short resource_type;
        private short resource_class;
        protected int ttl;
        protected short data_length;

        public Resource(byte[] data){
            buffer = ByteBuffer.wrap(data);
            decode_resource();
        }

        private void decode_resource(){
            //ByteBuffer buffer = ByteBuffer.wrap(data);

            // isPointer?
            if((buffer.get(index) & 0xc0) == 0xc0){
                pointer = (buffer.getShort(index) & 0x3f);
            } else {
                pointer = buffer.getShort(index);
            }

            name = extract_domain(buffer, pointer);

            index += 2; // Move past the pointer/label

            // Type
            resource_type = buffer.getShort(index);

            // Class
            index += 2;
            resource_class = buffer.getShort(index);

            // TTL
            index += 2;
            ttl = buffer.getInt(index);

            // Data length
            index += 4; // We grabbed an int before
            data_length = buffer.getShort(index);

            index += 2; // Last short, everything else is left to subclasses
        }
    }

    public class AnswerResource extends Resource {
        private InetAddress ip;

        public AnswerResource(byte[] data){
            super(data);

            extract_ip(buffer, index, data_length);
        }

        private void extract_ip(ByteBuffer buffer, int offset, int length){
            //InetAddress answer = new InetAddress();
            byte[] address = new byte[length];
            for(int i = 0; i < data_length; i++){
                address[i] = buffer.get(offset+i);
            }
            try{
                ip = InetAddress.getByAddress(address);
            } catch(UnknownHostException e){
                System.out.println("IP address is malformed");
            }
            index = index + length;
            //return answer;
        }

        private void print_answer(){
            System.out.println(super.name);
            System.out.println(super.ttl);
            System.out.println(ip.getHostAddress());
        }

    }

    public class NSResource extends Resource {
        private String name_server = new String();

        public NSResource(byte[] data){
            super(data);

            extract_nameserver(buffer, index);
            System.out.println(name_server);
        }

        private void extract_nameserver(ByteBuffer buffer, int offset){
            name_server = extract_domain(buffer, offset);
        }
    }

    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records. 
}


