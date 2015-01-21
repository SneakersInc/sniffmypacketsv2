sniffmypacketsv2
================

Next major release of sniffMyPackets - Now with added packet loving

###NOTE:  This version of sniffMyPackets requires a MongoDB backend (currently) to store packet information in. If you don't have one of these then you can find one in this repo:  
https://github.com/SneakersInc/sniffmypacketsv2-web
  
  
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
```
git clone https://github.com/allfro/canari.git  
cd canari  
python setup.py install  
```
This will install Canari and download the required dependencies.

Once installed you can test by running:

```canari version ``` 
You should see something like this:  

Your running *Canari Framework v1.1*

You are now ready to install sniffMyPacketsv2...

From your working directory clone the github repo using:
```
git clone https://github.com/SneakersInc/sniffmypacketsv2.git  
cd sniffmypacketsv2  
  ```
You now need to install the Python modules required. You can do this one of two ways:
```
1. sudo pip install -r requirements.txt  
2. sudo python setup.py install  

cd src  
canari create-profile sniffmypacketsv2 -w [working directory]   
```
so in my case:
```
-w /root/localTransforms/sniffmypacketsv2/src
  ```
This will create a sniffMyPacketsv2.mtz file

Open Maltego, click on the Maltego Icon in the toolbar, then Import - Import Configuration

Follow the wizard to install the transforms, entities and machine into Maltego

All the sniffMyPacketsv2 transforms and entities are under the [SmP] headings
