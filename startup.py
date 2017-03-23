import fauxmo
import logging
import time

from time import gmtime, strftime
from debounce_handler import debounce_handler
from subprocess import call

logging.basicConfig(level=logging.DEBUG)

class device_handler(debounce_handler):
    """Publishes the on/off state requested,
       and the IP address of the Echo making the request.
    """
    TRIGGERS = {"hal": 52000, "sal" : 52001, "kit" : 52002 }

    def act(self, client_address, state, name):

        print strftime("%Y-%m-%d %H:%M:%S", gmtime()), "State", state, "on ", name, "from client @", client_address
        # True is on
        if name == 'sal':
                if state == True:
                        print "Turning on SAL"
                        call(["sudo","etherwake","-i","eth0","xxxxxxxxxxxx"])
                if state == False:
                        print "Turning off SAL"
                        call(["ssh","sal","sudo","shutdown","-h","now"])
        if name == 'hal':
                if state == True:
                        print "Turning on HAL"
                        call(["sudo","etherwake","-i","eth0","xxxx"])
                if state == False:
                        print "Turning off HAL"
                        call(["ssh","hal","sudo","shutdown","-h","now"])
        if name == 'kitt':
                if state == True:
                        print "Turning on KITT"
                        call(["sudo","etherwake","-i","eth0","xxxxx"])
                if state == False:
                        print "Turning off KITT"
                        call(["ssh","kitt","sudo","shutdown","-h","now"])
        return True

if __name__ == "__main__":
    # Startup the fauxmo server
    fauxmo.DEBUG = True
    p = fauxmo.poller()
    u = fauxmo.upnp_broadcast_responder()
    u.init_socket()
    p.add(u)

    # Register the device callback as a fauxmo handler
    d = device_handler()
    for trig, port in d.TRIGGERS.items():
        fauxmo.fauxmo(trig, u, p, None, port, d)

    # Loop and poll for incoming Echo requests
    logging.debug("Entering fauxmo polling loop")
    while True:
        try:
            # Allow time for a ctrl-c to stop the process
            p.poll(100)
            time.sleep(0.1)
        except Exception, e:
            logging.critical("Critical exception: " + str(e))
            break

