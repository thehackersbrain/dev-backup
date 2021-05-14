---
title: How to hide files inside audio or music file using hiddenwave
author: Gaurav Raj
date: 2021-05-15 01:27:00 +0800
categories: [Tutorials]
tags: [stego, steganography, audio-stego, audio-steganography, hiddenwave, mr-robot, thehackersbrain]
image:
  src: /assets/hiddenwave/banner.png
  alt: Banner Image
---

Have you ever wished to hide your secret files like Mr. Robot do, inside of an audio file. I Don't Know about you but I was facinated by this tricks. It's seems like magic. So, for hiding our files inside any audio file, I've Created a tool called `Hiddenwave`. you can find it [here](https://github.com/thehackersbrain/hiddenwave)

## What is Hiddenwave ??
Well, Hiddenwave is an audio steganography tool written in **C++** for hiding your files or messages inside a `.wav` or `.mp3` audio file. You might be wondering, In **C++** ?? You could have done it easily in **Python**. Yeah! I could but we are hackers Gentleman, We love challenges.

**NOTE:** This tool only supports the `.mp3` and `.wav` audio files and can hide any other files inside the audio file.

## Requirement

Here's the Requirements for `hiddenwave` tool to get it up and running on you system.

- [libboost-all-dev](https://packages.debian.org/search?keywords=libboost-all-dev)
    ```
    sudo apt install libboost-all-dev -y
    ```
- [cmake](https://cmake.org/)
    ```
    sudo apt install cmake -y
    ```

## Features Added
- [x] Adding Support to hide files inside audio files
- [x] Adding Support to `.mp3` files
- [x] Improving UI by adding some colors

## Installation and Uses

There are tree ways to get this tool up and running on your system. 

### Binary File (Recommanded)
If you don't like to play with the source code or any installation things, you can just simply download the binary file from the [release](https://github.com/thehackersbrain/hiddenwave/releases/) page and start using it. Recommanded way for Newbies or anyone who just don't want to get in any trouble while installing dependencies. you can get this [here](https://github.com/thehackersbrain/hiddenwave/releases/download/1.2.1/hiddenwave)

### Automated Installation (Recommanded)
If you want to get the source code and want to build the whole package from yourself, then it's the easiest way to get the tool up and running with the source code clonned locally. All you have to do is just change the directory to where you want to install this tool and run the follwing command. Pretty straight Right ?? I Know :)
```bash
curl https://raw.githubusercontent.com/thehackersbrain/hiddenwave/main/install.sh -s | bash
```

### Manual Installation

And for those who are advanced and hard core fan of the terminal, you know what to do with it ;)

- Make Sure all requirements are installed
```bash
sudo apt install libboost-all-dev cmake -y
```
- Git clone this repo and change the directory
```bash
git clone https://github.com/thehackersbrain/hiddenwave.git && cd hiddenwave
```
- Now Build the package
```bash
mkdir build && cd build && cmake ..
```
- Now make the final binary
```bash
make
```
- Copy the binary in `/usr/bin/` for easy access \(optional\)
```bash
sudo cp hiddenwave /usr/bin/
```

## How to Use

Now let's see how to use this tool. Currently at the time of writing this article, this tool \(`hiddenwave`\) only supports two audio formats `.wav` and `.mp3`.

Let's see how to hide our files or messages inside the audio file.

### Hiding Data
- For hiding files inside `.wav` or `.mp3` audio file.
    ```bash
    ./hiddenwave -i input.wav -f filetobehidden.txt -o output.wav
    ```

    run the above command for hidding any files inside the music file. where `input.wav` is the file in which we are going to hide our data and instead of `.wav` file you can also use `.mp3` file, `filetobehidden.txt` is the file which we are going to hide inside the `input.wav` file and `output.wav` file is the output file which will be generated after hiding the file inside the audio.

    ![hidding file](/assets/hiddenwave/hidden_file.png)

- For hiding message inside `.wav` or `.mp3` audio file.
    ```bash
    ./hiddenwave -i input.wav -m 'Dummy Message' -o output.wav
    ```

    run the above command to hide your message inside the `.mp3` or `.wav` file. where `input.wav` file is the audio file in which we are going to hide of message, `Dummy Message` is the message which we are going to hide inside the audio file \(make sure the message is wrapped in single quotes ''\) and the `output.wav` file is the output file which will be generated after hidding the message on the audio file.

    ![hidding message](/assets/hiddenwave/hidden_message.png)

### Extracting Data

```bash
./hiddenwave -i output.wav
```

Extracting file or message from the audio file is pretty straight forward, run the above command where the `output.wav` file is the audio file which contains the hidden file or message.

- If the hidden data is a file, it will be extracted on the current directory named `output`.
![Extract File](/assets/hiddenwave/hidden_extract_file.png)

- If the hidden data is some message, it will be printed on the terminal.
![Extract Message](/assets/hiddenwave/hidden_extract_message.png)

Having any issue or suggestions regarding this tool or anything, hit me up on [twitter](https://twitter.com/thehackersbrain) or create a issue on [github](https://github.com/thehackersbrain/hiddenwave).

That's it for now, Hope I'll see you again, Don't forget to Share if you liked it.
