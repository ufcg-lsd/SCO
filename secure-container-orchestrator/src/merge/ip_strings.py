class IPStrings:

    initial_network_address = "172.20.0.0"
    current_network_address = None
    second_group_address_index = 5


    def find_next_dot(self, start_index, address):
        current_character = ""
        index = start_index
        while current_character != ".":
            current_character = address[index]
            index += 1
        return index - 1

#INCREASE_CURRENT_NETWORK: increases the second group of the current cluster network address by 1
    def increase_current_network(self):
        if self.current_network_address == None:
            self.current_network_address = self.initial_network_address
        first_group_end = self.find_next_dot(0, self.current_network_address)
        first_slice = self.current_network_address[0:first_group_end]
        second_group_end = self.find_next_dot(first_group_end + 1, self.current_network_address)
        second_slice = self.current_network_address[first_group_end + 1:second_group_end]
        third_slice = self.current_network_address[second_group_end:]
        second_slice = int(second_slice)
        second_slice += 1
        second_slice = str(second_slice)
        self.current_network_address = first_slice + "." +  second_slice + third_slice
        return self.current_network_address


#GET_CURRENT_NETWORK: returns the current network
    def get_current_network(self):
        if self.current_network_address == None:
            return self.increase_current_network()
        network = self.current_network_address
        print("network is " + network)
        network = self.increase_current_network()
        return network

