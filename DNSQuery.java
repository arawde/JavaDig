import java.io.ByteArrayOutputStream;
import java.util.Random;


public class DNSQuery {
    private byte[] query;
    private byte[] query_id;
    private byte flags;
    private byte response_code;
    private byte[] qd_count;
    private byte[] ancount;
    private byte[] nscount;
    private byte[] fqdn;
    private byte[] qtype;
    private byte[] qclass;


    public DNSQuery(String domain) {
        query = construct_query(domain);
    }

    private static byte[] get_query(){
        return this.query;
    }

    private static byte[] construct_query(String domain){
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        // We tried byte[] and ByteBuffer[], but we want the dynamic memory of this stream

        // Query ID
        Random r = new Random(); // Let's make a query ID
        int id = r.nextInt(32761) + 1; // But we don't want one that is 0
        this.query_id = {(byte) (id &0xff), (byte) ((id >>> 8) &0xff)};

        // Flags
        this.flags = (byte) 0x00; // 4.1.1 RFC 1035, we are making a query

        // Response code
        this.response_code = (byte) 0x00; // Same as above

        // Query Count
        this.qdcount = {(byte) 0x00, (byte) 0x01}; // One query a ah ah

        // Answer count
        this.ancount = {(byte) 0x00, (byte) 0x00};

        // Name Server Records
        this.nscount = {(byte) 0x00, (byte) 0x00};

        // Additional Record Count
        this.arcount = {(byte) 0x00, (byte) 0x00};

        // QNAME
        this.encode_domain(domain);

        // QTYPE
        this.qtype = {(byte) 0x00, (byte) 0x01};

        // QCLASS
        this.qclass = {(byte) 0x00, (byte) 0x01};

        buffer.write(query_id, 0, query_id.length);
        buffer.write(flags);
        buffer.write(response_code);
        buffer.write(qdcount, 0, qdcount.length);
        buffer.write(ancount, 0, ancount.length);
        buffer.write(nscount, 0, nscount.length);
        buffer.write(arcount, 0, arcount.length);
        buffer.write(fqdn, 0, fqdn.length);
        buffer.write((byte) 0x00); // End of QNAME
        buffer.write(qtype, 0, qtype.length);
        buffer.write(qclass, 0, qclass.length);

        return buffer.toByteArray();
    }

    private static void encode_domain(String domain){
        this.fqdn = new byte[domain.length() + 1];
        String[] fqdnParts = domain.split("[.]");

        int accumulator = 0;
        for (int i = 0; i < fqdnParts.length; i++){
            fqdn[accumulator] = (byte) fqdnParts[i].length();

            for (int j = 0; j< fqdnParts[i].length(); j++) {
                fqdn[++accumulator] = (byte) (fqdnParts[i].charAt(j));
            }

            accumulator++;
        }
    }

}


