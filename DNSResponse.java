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
    private boolean is_cname = false;
    private int response_code = 0;
    private int answer_count = 0;
    private int ns_count = 0;
    private int additional_count = 0;
    private String fqdn = new String();
    private short qtype;
    private short qclass;
    private AnswerResource[] answers;
    private NSResource[] name_servers;
    private AdditionalResource[] additional_resources;
    private boolean decoded = false;      // Was this response successfully decoded

    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

	void dumpResponse() {
        System.out.printf("%s %d %s %s%n",
                "Response ID:", queryID, "Authoritative: ", String.valueOf(check_authoritative()));

        print_answers();
        print_nameservers();
        print_additional();
	}

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

	public DNSResponse (byte[] data, int len) {
        decode_query(data);

        // Error cases
        if(response_code == 3){
            System.out.printf("%s %s %s%n", fqdn, -1, "0.0.0.0");
        }
        if(response_code != 0){
            System.out.printf("%s %s %s%n", fqdn, -4, "0.0.0.0");
        }

        index += 2; // We want to increment past the end of the query

        // Extract answers
        if(answer_count > 0){
            answers = new AnswerResource[answer_count];
            for(int i = 0; i < answer_count; i++) {
                answers[i] = new AnswerResource(data);
            }
        }

        // Extract name servers
        if(ns_count > 0){
            name_servers = new NSResource[ns_count];
            for(int i = 0; i < ns_count; i++){
                name_servers[i] = new NSResource(data);
            }
        }

        // Extract additional resources
        if(additional_count > 0){
            additional_resources = new AdditionalResource[additional_count];
            for(int i = 0; i < additional_count; i++){
                additional_resources[i] = new AdditionalResource(data);
            }
        }
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
        if((rc &0xff) != 0x00){
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
        String domain = new String();


        while((data.get(offset) != 0x00) && (0xc0 != (data.get(offset) & 0xc0))){
            i = 0;
            label = data.get(offset);
            while(i < label){
                i++;
                offset++;
                c = (char) data.get(offset);
                domain = domain.concat(Character.toString(c));
            }
            domain = domain.concat(".");
            offset++;
        }
        if((data.get(offset) & 0xc0) == 0xc0){
            domain = domain.concat(extract_domain(data, data.getShort(offset) & 0x3f)); // Last 14 bits we dem boyz
        }
        if(data.get(offset) == 0x00){
            return domain = domain.substring(0, domain.length() -1);
        }
        return domain;
    }

    public boolean has_answers(){
        return (answer_count > 0);
    }

    public boolean has_additional(){
        return (additional_count > 0);
    }

    public boolean check_authoritative(){
        return is_authoritative || is_cname;
    }

    public boolean check_response(){
        return (response_code == 0);
    }

    public InetAddress get_nameserver_ip(){
        return additional_resources[0].get_address();
    }

    public void final_answers(){
        for(int i = 0; i < answer_count; i++){
            System.out.printf("%s %d %s%n",
                    answers[i].get_name(),
                    answers[i].get_ttl(),
                    (answers[i].get_type() == "CNAME") ? answers[i].get_cname() : answers[i].get_ip());
        }
    }

    public void print_answers(){
        System.out.printf("  %s %d%n", "Answers", answer_count);

        for(int i = 0; i < answer_count; i++){
            answers[i].print_answer();
        }
    }

    public void print_nameservers(){
        System.out.printf("  %s %d%n", "Nameservers", ns_count);

        for(int i = 0; i < ns_count; i++){
            name_servers[i].print_nameserver();
        }
    }

    public void print_additional(){
        System.out.printf("  %s %d%n", "Additional Information", additional_count);

        for(int i = 0; i < additional_count; i++){
            additional_resources[i].print_additional();
        }
    }

    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.

    public class Resource {
        protected ByteBuffer buffer;
        protected String name = new String();
        private int pointer;
        protected short resource_type;
        protected short resource_class;
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
                pointer = (buffer.getShort(index) & 0x3fff);
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

        public String get_type(){
            switch(resource_type){
                case 1:
                    return "A";
                case 2:
                    return "NS";
                case 5:
                    return "CNAME";
                case 6:
                    return "SOA";
                case 28:
                    return "AAAA";
                default:
                    return "A";
            }
        }
    }

    public class AnswerResource extends Resource {
        protected InetAddress ip;
        protected String cname;

        public AnswerResource(byte[] data){
            super(data);
            //System.out.println(index);
            if(super.get_type() == "CNAME"){
                cname = extract_domain(buffer, index);
            } else {
                extract_ip(buffer, index, data_length);
            }
        }

        private void extract_ip(ByteBuffer buffer, int offset, int length){
            byte[] address = new byte[length];
            for(int i = 0; i < data_length; i++){
                address[i] = buffer.get(offset+i);
            }
            try{
                ip = InetAddress.getByAddress(address);
            } catch(UnknownHostException e) {
                System.out.println("IP address is malformed");
            }
            index = index + length;
        }

        private String get_name(){
            return name;
        }

        private String get_cname(){
            return cname;
        }

        private int get_ttl(){
            return ttl;
        }

        private String get_ip(){
            return ip.getHostAddress();
        }

        private void print_answer(){
            System.out.format("      %-30s %-10d %-4s %d\n",
                    name, ttl, resource_type, resource_class);
        }
    }

    public class NSResource extends Resource {
        private String name_server = new String();

        public NSResource(byte[] data){
            super(data);

            extract_nameserver(buffer, index);
            if(resource_type == 28){

            }
        }

        private void extract_nameserver(ByteBuffer buffer, int offset){
            name_server = extract_domain(buffer, offset);
            index += data_length;
        }

        private void print_nameserver(){
            System.out.format("      %-30s %-10d %-4s %s\n",
                    name, ttl, get_type(), name_server);
        }
    }

    public class AdditionalResource extends AnswerResource {
        public AdditionalResource(byte[] data){
            super(data);
        }

        public InetAddress get_address(){
            return ip;
        }

        private void print_additional(){
            System.out.format("      %-30s %-10d %-4s %s\n",
                    name, ttl, get_type(), super.get_ip());
        }
    }

    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records. 
}


