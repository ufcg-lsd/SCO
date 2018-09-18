from load_balancer import LoadBalancer

class Node:
    ip = None
    lbs = None


    def __init__(self, ip):
        self.ip = ip
        self.lb_ips = []

    def get_ip(self):
        return self.ip
 
    def set_ip(self, ip):
        self.ip = ip

    def get_lb_ips(self):
        return self.lb_ips

    def set_lb_ips(self, lb_ips):
        self.lb_ips = lb_ips
   
    def add_lb(self, image, ip):
        lb_index = 0
        for lb in lbs:
            if lb.get_image() == image:
                lbs[lb_index] = LoadBalancer(image, ip)
                return True
            lb_index += 1
        load_balancer = LoadBalancer(image, ip)
        self.lbs.append((load_balancer))
        return True
        
