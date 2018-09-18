class LoadBalancer:
    ip = None
    containers = None


    def __init__(self, ip):
       self.ip = ip
       self.containers = []
    
    def get_containers(self):
        return self.containers

    def set_containers(self, containers):
        self.containers = containers
    
    def add_container(self, container):
        self.containers.append(container)
        
    def remove_container(self, container):
        self.containers.remove(container)

    def get_ip(self):
        return self.ip

    def set_ip(self, ip):
        self.ip = ip

