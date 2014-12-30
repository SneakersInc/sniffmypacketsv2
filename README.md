sniffmypacketsv2
================

Next major release of sniffMyPackets - Now with added packet loving


These instructions are to install sniffMyPacketsv2 onto your machine. In order for the transforms to work you need to have the following 2 components installed:

1. Maltego

2. Canari Framework

1. Maltego

Download Maltego from their website or if you are using BackTrack/Kali its installed by default.

Run Maltego so it creates the required folders and directory structure
Go through the default configuration for the first run (that wizard thing)
Close Maltego
2. Canari Framework

The recommended method is to get Canari from the github repo here:

Canari Framework

From the directory you wish to have Canari installed run the following commands:

git clone https://github.com/allfro/canari.git
cd canari
python setup.py install
This will install Canari and download the required dependencies.

Once installed you can test by running:

canari version
You should see something like this:

Your running *Canari Framework v1.1*
You are now ready to install sniffMyPacketsv2...

From your working directory clone the github repo using:

git clone https://github.com/catalyst256/sniffMyPacketsv2.git
cd sniffMyPacketsv2/src
canari create-profile sniffMyPacketsv2 -w [working directory] 
so in my case:

-w /root/localTransforms/sniffMyPacketsv2/src
This will create a sniffMyPacketsv2.mtz file

Open Maltego, click on the Maltego Icon in the toolbar, then Import - Import Configuration

Follow the wizard to install the transforms, entities and machine into Maltego

All the sniffMyPacketsv2 transforms and entities are under the [SmP] headings