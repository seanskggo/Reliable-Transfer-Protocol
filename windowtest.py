from helper import SenderWindow

window = SenderWindow(4)

window.add(1, 1)
window.add(2, 1)
window.add(3, 1)
window.add(4, 1)

window.ack(1)
# window.ack(2)
window.ack(3)
window.ack(4)



# window.add(5, 1)
# window.add(6, 1)
# window.add(7, 1)

# window.ack(4)

window.printWindow()