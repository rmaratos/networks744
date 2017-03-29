from tkinter import Tk, Canvas, CENTER, ALL, Entry, TOP, BOTH
import random
from enum import Enum
import matplotlib
matplotlib.use('TkAgg')

from numpy import arange, sin, pi
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np
from pcap import Monitor

import sys

class Mode(Enum):
    """Animation Modes"""
    START = 0
    SETUP = 1
    MAIN = 2


class Button(object):
    """Basic Button Class for Animations"""
    def __init__(self, cx, cy, width, height, text):
        self.cx, self.cy = cx, cy
        self.x0 = cx - width/2
        self.x1 = cx + width/2
        self.y0 = cy - height/2
        self.y1 = cy + height/2
        self.text = text

    def clicked(self, x, y):
        """Click on rectangular region of button"""
        return (self.x0 <= x <= self.x1) and (self.y0 <= y <= self.y1)

    def draw(self, canvas):
        """Draw button rectangle and text"""
        cx, cy = self.cx, self.cy
        canvas.create_text(cx, cy, text=self.text, font=("Impact", 32))
        canvas.create_rectangle(self.x0, self.y0, self.x1, self.y1)

class Visual(object):
    def __init__(self, pcap_file, mac, width=800, height=600):
        root = Tk()
        self.root = root
        self.margin = 0.12*height
        self.width, self.height = width, height - self.margin
        self.cx, self.cy = width/2, (height - self.margin)/2
        self.toolbar = \
            Canvas(self.root, width=self.width, height=self.margin)
        self.toolbar.pack()

        self.pcap_file = pcap_file
        self.mac = mac
        self.canvas = Canvas(root, width=width, height=height - self.margin)
        # self.canvas.pack()
        self.init_animation()
        root.bind("<Button-1>", lambda e: self.mouse_event(e))
        root.bind("<Key>", lambda e: self.key_event(e))
        root.mainloop()


    def draw_start_screen(self):
        """Start screen text"""
        self.canvas.delete(ALL)
        cx, cy = self.width/2, self.height/2
        font = ("Impact", "128")
        self.canvas.create_text(cx, 0.8*cy, text="Wi-Fi Snooper", font=font)
        font = ("Impact", 32)
        self.canvas.create_text(cx, 1.5*cy, text="Press s to Begin", font=font)

    def draw_toolbar(self):
        """Toolbar for main animation"""
        self.toolbar.create_text(self.cx, 0.1*self.cy, text=sys.argv[1],
                                 font=("Impact", 32))
        self.toolbar.create_text(self.cx, 0.3*self.cy, text="Type of Activity: ",
                                 font=("Impact", 32))
        self.toolbar.create_text(self.cx*0.05, 0.1*self.cy,
                                 text="Q to quit",
                                 font=("Impact", 20), anchor="w")

    def draw_all(self):
        """Refresh frame for infection animation"""
        print "redraw_all"
        # self.canvas.delete(ALL)
        f = Figure(figsize=(5, 4), dpi=100)
        self.sent_subplot = f.add_subplot(121)
        self.sent_subplot.set_xlabel('Time (seconds)')
        self.sent_subplot.set_ylabel('Bandwidth (bytes)')
        self.sent_subplot.set_title('Sent Traffic')
        self.received_subplot = f.add_subplot(122)
        self.received_subplot.set_xlabel('Time (seconds)')
        self.received_subplot.set_ylabel('Bandwidth (bytes)')
        self.received_subplot.set_title('Received Traffic')



        # self.canvas.destroy()
        self.canvas2 = FigureCanvasTkAgg(f, master=self.root)
        self.canvas2.show()
        self.canvas2.get_tk_widget().pack(side=TOP, fill=BOTH, expand=1)



        #
        # #running FFT on the data
        #
        # #t = np.arange(256)
        # sp = np.fft.fft(c.received_buckets)
        # freq = np.fft.fftfreq(t.shape[-1])
        # plt.plot(freq, sp.real, freq, sp.imag)
        # plt.show()



        self.update_plot()
        print "raised"

    def update_plot(self):
        m = Monitor(self.pcap_file, self.mac, scan=True)
        c = m.client #computer
        if not c:
            print "C is none"
            return
        bucket, delta = c.buckets()
        print "SENT"
        print c.sent_buckets
        print "RECEIVED"
        print c.received_buckets
        t = np.arange(0, delta, bucket)
        self.sent_subplot.clear()
        self.received_subplot.clear()
        self.sent_subplot.axis([0,delta,0, max(c.sent_buckets)])
        self.sent_subplot.plot(t, c.sent_buckets)
        self.sent_subplot.axis([0,delta,0, max(c.received_buckets)])
        self.received_subplot.plot(t, c.received_buckets)
        # plt.pause(0.05)
        self.canvas2.draw()


    def timer_fired(self):
        """Called every frame refresh"""
        print "timer_fired", self.mode
        if self.mode == Mode.START:
            pass
        if self.mode == Mode.MAIN and not self.paused:
            self.update_plot()

    def timer(self):
        """Setup timer loop"""
        self.timer_fired()
        self.canvas.after(self.timer_delay, self.timer)

    def init_animation(self):
        """Initialize or reset animation"""
        self.users = []
        self.timer_delay = 10
        self.start_counter = 0
        self.versions = 40
        self.max_users = 100
        self.version = None
        self.paused = False
        # self.mode = Mode.START
        # self.draw_start_screen()
        self.mode = Mode.MAIN
        # self.redraw_all()
        self.error_text = None
        self.error_font_size = 20
        self.version_select = None
        self.start()
        self.timer()

    def start(self):
        """Initialize and start"""
        self.draw_toolbar()
        self.mode = Mode.MAIN
        self.draw_all()


    def mouse_event(self, e):
        """Process click event"""
        x, y = e.x, e.y
        if self.mode == Mode.SETUP:
            if self.button.clicked(x, y):
                self.start()
        if self.mode == Mode.MAIN:
            pass

    def key_event(self, e):
        """Process keyboard event"""
        if e.keysym == 'r':
            self.init_animation()
            self.paused = False
        elif e.keysym == 'p':
            self.paused = not self.paused
        elif e.keysym == 's' and self.mode == Mode.START:
            self.mode = Mode.MAIN
            # self.draw_setup_screen()
            self.start()
        elif e.keysym == 'b' and self.mode == Mode.SETUP:
            self.start()
        elif e.keysym == 'q':
            self.root.destroy()

if len(sys.argv) != 3:
    print "Usage visual.py pcap_file mac_address"
else:
    Visual(sys.argv[1], sys.argv[2])
