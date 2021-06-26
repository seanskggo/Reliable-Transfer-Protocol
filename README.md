# Reliable Transfer Protocol

Implementation of reliable transfer protocol over UDP.

Aim: simulate TCP socket connection using UDP through establishing a custom reliable channel. Packet loss is artificially simulated since this occurence is rare over localhost.

MWS = Maximum Window Size

MSS = Maximum Segment Size

pdrop = Packet Loss Probability 

Reciever:

``` python receiver.py receiver_port FileReceived.txt ```

Sender:

``` python sender.py receiver_host_ip receiver_port FileToSend.txt MWS MSS timeout pdrop seed ```

