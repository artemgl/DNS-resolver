import dns
import dns.query
import socket
import json
import time

#                 a
root_servers = ['198.41.0.4',
                # b
                '199.9.14.201',
                # c
                '192.33.4.12',
                # d
                '199.7.91.13',
                # e
                '192.203.230.10',
                # f
                '192.5.5.241',
                # g
                '192.112.36.4',
                # h
                '198.97.190.53',
                # i
                '192.36.148.17',
                # j
                '192.58.128.30',
                # k
                '193.0.14.129',
                # l
                '199.7.83.42',
                # m
                '202.12.27.33']

server_to_resolve_dns_server_domain = '8.8.8.8'


def create_response(query):
    domain = query.question[0].name.to_text()
    rdatatype = query.question[0].rdtype

    if rdatatype == dns.rdatatype.A:
        filename = "cacheIPv4.txt"
    elif rdatatype == dns.rdatatype.AAAA:
        filename = "cacheIPv6.txt"
    else:
        return None

    current_time = time.time()

    f = open(filename, 'r')
    cache = json.loads(f.readline())
    f.close()

    pair = cache.get(domain)
    if pair is not None:
        time_, addresses = pair

        if current_time < time_:
            if rdatatype == dns.rdatatype.A:
                rdtype = "A"
            elif rdatatype == dns.rdatatype.AAAA:
                rdtype = "AAAA"
            else:
                return None

            ttl = int(time_ - current_time)
            answers = ''.join([domain + " " + str(ttl) + " IN " + rdtype + " " + address + "\n" for address in addresses])
            response = dns.message.from_text("id " + str(query.id) + "\n"
                                             "opcode QUERY\n"
                                             "rcode NOERROR\n"
                                             "flags QR\n"
                                             ";QUESTION\n" +
                                             domain + " IN " + rdtype + "\n"
                                             ";ANSWER\n" +
                                             answers +
                                             ";AUTHORITY\n"
                                             ";ADDITIONAL\n")
            return response

    response = find_response(query)
    answer = response.answer
    if len(answer) > 0:
        cache[domain] = (current_time + answer[0].ttl), [entry.to_text() for entry in answer[0]]

        f = open(filename, 'w')
        f.write(json.dumps(cache))
        f.close()

    return response


def find_response(query):
    domain = query.question[0].name

    server = root_servers[0]
    response = dns.query.udp(query, server)
    while len(response.answer) == 0:
        server_entry = None
        for entry in response.additional:
            if entry.rdtype == dns.rdatatype.A:
                server_entry = entry
                break

        if server_entry is None:
            dns_servers = response.get_rrset(dns.message.AUTHORITY, domain, dns.rdataclass.IN, dns.rdatatype.NS)

            if dns_servers is None or len(dns_servers) == 0:
                break

            subquery = dns.message.make_query(dns_servers[0].to_text(), dns.rdatatype.A)
            response_for_dns = dns.query.udp(subquery, server_to_resolve_dns_server_domain)

            for entry in response_for_dns.answer:
                if entry.rdtype == dns.rdatatype.A:
                    server_entry = entry

            if server_entry is None:
                break

        server = server_entry[0].to_text()

        response = dns.query.udp(query, server)

    return response


if __name__ == '__main__':
    port = 53
    ip = "127.0.0.1"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    while True:
        query, _, destination = dns.query.receive_udp(sock)
        answer = create_response(query)
        dns.query.send_udp(sock, answer, destination)
