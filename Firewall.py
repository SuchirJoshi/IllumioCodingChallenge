import pandas as pd

class Firewall:
    def __init__(self, csv_file):
        self.csv = pd.read_csv(csv_file, names=["direction", "protocol", "port", "ip_address"])

        #this part returns 2 columns, one containing
        #the lowest number in the range of each entry, the other the highest number in the range,
        #for both port and ip columns. This allows for easy comparison later
        port_raw = self.csv["port"]
        port_modified_low, port_modified_high = get_number_range(port_raw)
        ip_address_raw = self.csv["ip_address"]
        ip_address_modified_low, ip_address_modified_high = get_number_range(ip_address_raw)

        #This part adds them to the csv
        self.csv["port_low"] = port_modified_low
        self.csv["port_high"] = port_modified_high

        self.csv["ip_low"] = ip_address_modified_low
        self.csv["ip_high"] = ip_address_modified_high

    def accept_packet(self, direction, protocol, port, ip_address):
        criteria_1 = self.csv["direction"] == direction
        criteria_2 = self.csv["protocol"] == protocol
        criteria_3 = self.csv["port_low"] <= port
        criteria_4 = self.csv["port_high"] >= port

        ip_low, ip_high = get_number_range([ip_address])
        criteria_5 = self.csv["ip_low"] <= ip_low
        criteria_6 = self.csv["ip_high"] >= ip_high

        all_criteria = criteria_1 & criteria_2 & criteria_3 & criteria_4 & criteria_5 & criteria_6

        return self.csv[all_criteria].shape[0] >= 1

#This function takes in a column and returns two,
#one containing the low end values for each entry's range and the other containing the high end values
def get_number_range(column):
    low = [0 for i in range(len(column))]
    high = [1 for i in range(len(column))]

    index = 0
    for string in column:
        string = str(string)
        dash = string.find("-")
        if dash == -1:
            low[index] = get_number(string)
            high[index] = low[index]
        else:
            low[index] = get_number(string[:dash])
            high[index ]= get_number(string[dash + 1:])
        index += 1
    return low, high

#This function just returns back the number for port entries, but for ip entries,
#it converts each address to a unique number that is easy to compare. a.b.c.d becomes a00b00c00d
#abc.def.ghi.j becomes abcdefghi00j
def get_number(number):
    if (number.find(".") == -1):
        return int(number)
    list = number.split(".")
    num = int(list[0])*(10**9) + int(list[1])*(10**6) + int(list[2])*(10**3) + int(list[3])
    return num
