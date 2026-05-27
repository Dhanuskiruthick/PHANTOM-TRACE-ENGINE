suspicious_ports = [31,666,1234,3127,3128,4444, 1337, 6666,6667,27374,30100,31337]


def detect_suspicious_traffic(port):

    if port in suspicious_ports:

        return True

    return False