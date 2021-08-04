##################################################################
# Window Class Integration Test
##################################################################

##################################################################
# Imports
##################################################################

from helper import SenderWindow, ReceiverWindow, Slot

##################################################################
# Test
##################################################################

sender = SenderWindow(4)

sender.add(1, 1, "asdf")
sender.add(2, 1, "asdf")
sender.add(3, 1, "asdf")
sender.add(4, 1, "asdf")

sender.ack(1)
# sender.ack(2)
# sender.ack(3)
sender.ack(4)

sender.printWindow()

# receiver = ReceiverWindow(1, 1)
# sender = SenderWindow(4)

# # 1. Client sends packets 1, 2, 3, 4 to Server

# sender.add(1, 1)
# sender.add(2, 1)
# sender.add(3, 1)
# sender.add(4, 1)

# # 2. Server response

# sender.ack(receiver.send_cum_ack(1))
# sender.ack(receiver.send_cum_ack(2))
# sender.ack(receiver.send_cum_ack(3))
# sender.ack(receiver.send_cum_ack(4))

# # print(sender.data_to_resend())
# # sender.printWindow()

# receiver = ReceiverWindow(1, 1)
# sender = SenderWindow(4)

# sender.add(1, 1)
# sender.add(2, 1)
# sender.add(3, 1)
# sender.add(4, 1)

# sender.ack(1)
# # sender.ack(2)
# sender.ack(3)
# # sender.ack(4)
# sender.add(5, 1)
# # sender.add(6, 1)
# sender.ack(2)


# 2. Server response

# sender.ack(receiver.send_cum_ack(1))
# sender.ack(receiver.send_cum_ack(2))
# sender.ack(receiver.send_cum_ack(4))

# print(sender.data_to_resend())
# sender.printWindow()

# window.ack(1)
# window.ack(2)
# window.ack(3)
# window.ack(4)

# print(window.data_to_resend())

# # window.add(5, 1)
# # window.add(6, 1)
# # window.add(7, 1)

# # window.ack(4)

# window.printWindow()