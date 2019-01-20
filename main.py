import csv
from intervaltree import *


def is_interval(val):
    if "-" in val:
        return True
    return False

class Firewall:
    # parses CSV file
    def __init__(self, path):
    
        # take CSV data and convert
        # to 4 dictionaries, each corresponding to a possible direction+protocol combo
        self.inbound_tcp = IntervalTree()
        self.inbound_udp = IntervalTree()
        self.outbound_tcp = IntervalTree()
        self.outbound_udp = IntervalTree()


        with open(path, 'r') as f:
            file = csv.reader(f)
            list_of_rules = list(file)
        
        for line in list_of_rules:
            direction = line[0] 
            protocol = line[1] 
            port = line[2]
            ip_address = line[3]
          
            # creating ip_address interval tree
            if is_interval(ip_address):
                interval_list = ip_address.split("-")
                start = int(interval_list[0].replace(".", ""))
                end = int(interval_list[1].replace(".", ""))
                ip_address_interval_tree = IntervalTree([Interval(start, end+1)])
            else:
                int_ip_address = int(ip_address.replace(".", ""))
                ip_address_interval_tree = IntervalTree([Interval(int_ip_address, int_ip_address+1)])
    
            # creating port interval tree
            if is_interval(port):
                port_list = port.split("-")
                port_start = int(port_list[0])
                port_end = int(port_list[1])+1
                port_interval_tree = IntervalTree([Interval(port_start, port_end+1)])
                
                if direction == "inbound":
                    if protocol == "tcp":
                        self.inbound_tcp.add(Interval(port_start, port_end, ip_address_interval_tree))
                    else:
                        self.inbound_udp.add(Interval(port_start, port_end, ip_address_interval_tree))

                else:
                    if protocol == "tcp":
                        self.outbound_tcp.add(Interval(port_start, port_end, ip_address_interval_tree))
                    else:
                        self.outbound_udp.add(Interval(port_start, port_end, ip_address_interval_tree))
            else:
                port_interval_tree = IntervalTree([Interval(int(port), int(port)+1)]) 
                port = int(port)
                if direction == "inbound":
                    if protocol == "tcp":
                        self.inbound_tcp.add(Interval(port, port+1, ip_address_interval_tree))
                    else:
                        self.inbound_udp.add(Interval(port, port+1, ip_address_interval_tree))

                else:
                    if protocol == "tcp":
                        self.outbound_tcp.add(Interval(port, port+1, ip_address_interval_tree))
                    else:
                        self.outbound_udp.add(Interval(port, port+1, ip_address_interval_tree))

            
    def accept_packet(self, direction, protocol, port, ip_address):
        direction_plus_protocol = direction + "_" + protocol
        accepted = False
        int_ip = int(ip_address.replace(".", ""))

        if direction_plus_protocol == "inbound_tcp":
            port_exists = self.inbound_tcp.overlaps(port, port+1)
            if port_exists:
                for rule in sorted(self.inbound_tcp[port:port+1]):
                    accepted = rule.data.overlaps(int_ip, int_ip+1)
                    if accepted:
                        break
            else:
                return False
        elif direction_plus_protocol == "inbound_udp":
            port_exists = self.inbound_udp.overlaps(port, port+1)
            if port_exists:
                for rule in sorted(self.inbound_udp[port:port+1]):
                    accepted = rule.data.overlaps(int_ip, int_ip+1)
                    if accepted:
                        break
            else:
                return False
 
        
        elif direction_plus_protocol == "outbound_tcp":
            port_exists = self.outbound_tcp.overlaps(port, port+1)
            if port_exists:
                for rule in sorted(self.outbound_tcp[port:port+1]):
                    accepted = rule.data.overlaps(int_ip, int_ip+1)
                    if accepted:
                        break
            else:
                return False
 
        else:
            port_exists = self.outbound_udp.overlaps(port, port+1)
            if port_exists:
                for rule in sorted(self.outbound_udp[port:port+1]):
                    accepted = rule.data.overlaps(int_ip, int_ip+1)
                    if accepted:
                        break
            else:
                return False
 
        return accepted


if __name__ == '__main__':
    import pdb; pdb.set_trace()
    fw = Firewall("firewall.csv")
    import pdb; pdb.set_trace()
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))

