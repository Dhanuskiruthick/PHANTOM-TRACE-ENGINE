def log_packet(data):

    with open("packets.log", "a", encoding="utf-8") as file:

        file.write(data + "\n")