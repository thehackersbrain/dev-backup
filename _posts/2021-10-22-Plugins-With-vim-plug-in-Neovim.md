---
title: Plugins with vim-plug in NeoVim
author: Gaurav Raj
date: 2021-10-22 13:54:30 +0530
category: [NeoVim]
tags:
  [
    neovim,
    ide,
    neovim-as-ide,
    linux,
    command line,
    vim,
    vim-plug,
    thehackersbrain,
    gauravraj,
    gaurav raj,
  ]
image:
src: /assets/neovim/neovim-banner.png
---

Hello There Everyone, Myself **Gaurav Raj**, a cyber security student learning to secure things while breaking it ;).
I've using **Arch Linux** from about a year from now and It's been an awesome journey. And as you all know if you're
interested in Cyber Security or in any kind of tech releated field, you all would we familiar that how important it is
to have experience with linux systems. and somehow we like to do things from our terminal. if you're in any kind of tech
releated field then you must be using some kind of source code editors like vscode, atom, sublime or any other. So for
taking our linux experience to the next level, we will use **Vim** or say **Neovim** as our main editor for source codes
or any of our projects or as a general daily text editor for our work. for those who haven't heard of **vim** before
**Vim is a free and open-source, screen-based text editor program for Unix**. I've been using **vim** as my main text or
source code editor from about a few months from now and it never disappoints me. But it may take some time and practice
for being comfortable with it. Most people don't use it because it may difficult to switch from a highly featured source
code editors such as vscode to a fully command-line based text editor. It's a very exhaustible leaning curve for most of us.
But if you start using it as on daily basis, you're definetely going to fall in love with it. So with that said, let's start
installing and configuring our text editor or say an **IDE** as we like. So, In this series we're going to use **Neovim**
as our main editor, **Neovim is to enable new applications without compromising Vim's traditional roles**. or we can say
it's just makes easier for us to configure **vim** for using it as an full time **IDE** (Integrated Development Environment).

### Installing NeoVim

First of all we need to install Neovim in our system, if not already installed ;)

- On Mac
  ```
  brew install neovim
  ```
- Ubuntu
  ```
  apt install neovim
  ```
- Arch Linux
  ```
  pacman -S neovim
  ```

### Create Config Files

Now we need to create some of the configuration files for our newly intalled **NeoVim**.

- Make a config directory and create a `init.vim` file inside it.
  ```
  mkdir ~/.config/nvim/ && touch ~/.config/nvim/init.vim
  ```

### Installing Vim-Plug

Now it's time to instal the **Vim-Plug** inside our **NeoVim**

```bash
curl -fLo ~/.config/nvim/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
```

Now we will have a `plug.vim` file inside an `autoload` directory in here `~/.config/nvim/autoload/` which will load the file on start.

### Add a new file for plugins

We will create a sperate file called `plugins.vim` for adding plugins entries in it for making our configuration file look neat, clean and managable.

```bash
mkdir ~/.config/nvim/vim-plug/ && touch ~/.config/nvim/vim-plug/plugins.vim
```

### Let's add some plugins in there

Add the following configuration in `~/.config/nvim/vim-plug/plugins.vim` file

```vim
" auto-install vim-plug
if empty(glob('~/.config/nvim/autoload/plug.vim'))
  silent !curl -fLo ~/.config/nvim/autoload/plug.vim --create-dirs
    \ https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
  "autocmd VimEnter * PlugInstall
  "autocmd VimEnter * PlugInstall | source $MYVIMRC
endif

call plug#begin('~/.config/nvim/autoload/plugged')

    " Better Syntax Support
    Plug 'sheerun/vim-polyglot'
    " File Explorer
    Plug 'scrooloose/NERDTree'
    " Auto pairs for '(' '[' '{'
    Plug 'jiangmiao/auto-pairs'

call plug#end()
```

### Source our plugins

Add the following line in `~/.config/nvim/init.vim` for sourcing our `plugins.vim` file in the main **NeoVim** configuration file.

```bash
source $HOME/.config/nvim/vim-plug/plugins.vim
```

### Some Important Vim-Plug Commands

- Open nvim
  ```bash
  nvim
  ```
- Check the status of your plugins
  ```bash
  :PlugStatus
  ```
- Install all of your plugins mentioned in `plugins.vim` file
  ```bash
  :PlugInstall
  ```
- To update all of your plugins
  ```bash
  :PlugUpdate
  ```
- After the update we can press `d` to see the difference or to run
  ```bash
  :PlugDiff
  ```
- To remove pluins that are no longer defined in `plugins.vim` file
  ```bash
  :PlugClean
  ```
- If you want to upgrade the `vim-plug` itself
  ```bash
  :PlugUpgrade
  ```

### Full list of commands and docs

Check it out on github [here](https://github.com/junegunn/vim-plug)

Thanks's for reading, next part will be posted soon, Don't forget to share if you liked it and I will see you next time. Until
then **Keep Calm and Hack The Planet** (In an ethical way, of course).
