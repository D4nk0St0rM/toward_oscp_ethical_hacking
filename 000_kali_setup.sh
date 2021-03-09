#!/bin/bash

## D4nk0St0rM
#### #### #### #### spread l0v3, share kn0wl3dge #### #### #### ####
# Created after some inspiration from https://github.com/blacklanternsecurity/kali-setup-script
# Create user to not require password for sudo [sudo visudo / theUSER ALL=(ALL) NOPASSWD:ALL)

#### install some basic tools
sudo apt-get install figlet -y 2>/dev/null
sudo apt-get install toilet -y 2>/dev/null
sudo apt-get install tree -y 2>/dev/null

#### set up some colour referencing to change outputs depending on your preferences
RED='\e[1;31m'
NC='\e[0m' # No Color
reset_colour='\e[0m'
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
PURPLE='\e[1;35m'
CYAN='\e[1;36m'

#### welcome messages
printf "${GREEN}"
figlet -c D4nk0St0rM
printf "${NC}"
toilet -f future -F border spread l0v3 share kn0wl3ge --filter metal 
printf "${CYAN}"
figlet -c "lets do this"
printf "${NC}"

#### Run As Root - release if you want to run as root only install
#if [ "$HOME" != "/root" ]
#then
#    printf "This is to run as root... later gater\n"
#    exit 1
#fi

#### set variables for use in paths
curuse=$(whoami)
mytools="/opt/mytools"
virtenv="~/.virtualenv"


#### Check KDE Version for config changes
if [ "`which kwriteconfig5`" ]; then
    KWRITECONF=kwriteconfig5
    HOTKEYS="$HOME/.config/khotkeysrc"
    PLASMADESK="$HOME/.config/plasma-org.kde.plasma.desktop-appletsrc"
    KDEVER=5
else
    KWRITECONF=kwriteconfig
    HOTKEYS="$HOME/.kde/share/config/khotkeysrc"
    PLASMADESK="$HOME/.kde/share/config/plasma-desktop-appletsrc"
    KDEVER=4
fi

#### skip prompts in apt-upgrade, etc.
export DEBIAN_FRONTEND=noninteractive
alias apt-get='yes "" | apt-get -o Dpkg::Options::="--force-confdef" -y'

#### copy sources.list from git and replace
toilet -f term -F border --gay "sources.list from git"
wget https://raw.githubusercontent.com/D4nk0St0rM/general_linux_notes/main/sources.list
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bakup
sudo cp sources.list /etc/apt/sources.list
rm sources.list

# Add public key for Visual code studio & protonvpn
toilet -f term -F border --gay "visual code studio key add"
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EB3E94ADBE1229CF 
wget -q -O - https://repo.protonvpn.com/debian/public_key.asc | sudo apt-key add -


#### add sources for visual studio
toilet -f term -F border --gay "add sources for visual code studio"
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list' &>/dev/null
sudo apt-get install apt-transport-https
sudo apt-get update


####install visual code studio
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Install some things =======================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
toilet -f term -F border --gay "Microsoft Visual Code Studio"
sudo apt-get install code

##### install forticlient vpn for virtualhacking labs
toilet -f term -F border --gay "forticlient vpn"
cd Documents/vhl
wget https://www.virtualhackinglabs.com/wp-content/uploads/2017/03/forticlientsslvpn_linux_4.4_2336.tar.gz
tar -zxf forticlientsslvpn_linux_4.4_2336.tar.gz
rm forticlientsslvpn_linux_4.4_2336.tar.gz
mkdir ~/.fctsslvpn_trustca
cp /etc/ssl/certs/COMODO_RSA_Certification_Authority.pem ~/.fctsslvpn_trustca/
cp /etc/ssl/certs/USERTrust_RSA_Certification_Authority.pem ~/.fctsslvpn_trustca/
cd ~/


#### Tweaking the themeing and look
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}========Running in background...........======================${NC}"
echo -e "${GREEN}==================== - tweaking the theme=====================${NC}"
echo -e "${GREEN}==================== - setting language & text editor=========${NC}"
echo -e "${GREEN}==================== - clean up and create folders============${NC}"
echo -e "${GREEN}==================== - install python pip=====================${NC}"
echo -e "${GREEN}==================== - install python virtualenvs ============${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}============= !!Why is pip not already installed!! ===========${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

mkdir -p '/usr/share/wallpapers/wallpapers/' &>/dev/null

wallpaper_file="$(find . -type f -name Kali_dark_shadow_eye.jpg)"
if [[ -z "$wallpaper_file" ]]
        then
                sudo wget -P '/usr/share/wallpapers/wallpapers/' https://raw.githubusercontent.com/D4nk0St0rM/simple_linux_tweaks/main/wallpaper/Kali_dark_shadow_eye.jpg
        else
                sudo cp "$wallpaper_file" '/usr/share/wallpapers/wallpapers/Kali_dark_shadow_eye.jpg'
fi


#### commandline with oh-my-zsh
toilet -f term -F border --gay "... oh my zsh ..."
git clone http://github.com/robbyrussell/oh-my-zsh ~/.oh-my-zsh
sudo chsh -s $(which zsh)
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting
wget https://github.com/Lokaltog/powerline/raw/develop/font/PowerlineSymbols.otf https://github.com/Lokaltog/powerline/raw/develop/font/10-powerline-symbols.conf
sudo mv PowerlineSymbols.otf /usr/share/fonts/
sudo fc-cache -vf
sudo mv 10-powerline-symbols.conf /etc/fonts/conf.d/
cp ~/.zshrc ~/.zshrc_
mv -b ~/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
cat ~/.zshrc_ >> ~/.zshrc
### manually change .zshrc [to do - blanket config to curl into place
### ZSH_THEME="agnoster"
### plugins=(
###             git
###             zsh-syntax-highlighting
###             zsh-autosuggestions
###)


#### .config/kdeglobals
${KWRITECONF} --file kdeglobals --group "KDE-Global GUI Settings" --key "GraphicEffectsLevel" 0
${KWRITECONF} --file kdeglobals --group "General" --key "ColorScheme" "BreezeDark"
${KWRITECONF} --file kdeglobals --group "General" --key "Name" "Kali-Dark"
${KWRITECONF} --file kdeglobals --group "General" --key "shadeSortColumn" "true"
${KWRITECONF} --file kdeglobals --group "Icons" --key "Theme" "Flat-Remix-Blue-Dark"
${KWRITECONF} --file kdeglobals --group "KDE" --key "ColorScheme" "KaliDark"
${KWRITECONF} --file kdeglobals --group "KDE" --key "SingleClick" "false"
${KWRITECONF} --file kdeglobals --group "KDE" --key "widgetStyle" "Oxygen"
${KWRITECONF} --file plasmarc --group "Wallpapers" --key "usersWallpapers" "/home/$curuse/Pictures/Kali_dark_shadow_eye.jpg"
${KWRITECONF} --file plasmarc --group "Theme" --key "name" "breeze-dark"

#### Language setting
sudo setxkbmap -layout gb

#### Set default text editor
echo "export EDITOR=/usr/bin/nano" >> ~/.zshrc
echo "export VISUAL=/usr/bin/nano" >> ~/.zshrc

#### A litte folder management
toilet -f term -F border --gay "... folder management ..."
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
rmdir ~/Music ~/Public ~/Videos ~/Templates ~/Desktop &>/dev/null
mkdir -p ~/Documents/vhl 2>/dev/null
mkdir -p ~/Documents/htb 2>/dev/null
mkdir -p ~/Documents/general 2>/dev/null
mkdir -p ~/.virtualenv 2>/dev/null
mkdir -p /opt/mytools 2>/dev/null
mytools="/opt/mytools"
virtenv="~/.virtualenv"
mkdir -p ~/Downloads 2>/dev/null
sudo rm packages.microsoft.gpg &>/dev/null
wget https://github.com/D4nk0St0rM/Squirr3Lp4nda_ethical_hacking/raw/main/reporting/box_name_IP_template_v2.1.ctb
mv B0X_IP_Template..ctb ~/Documents/vhl/BOX_IP_Template.ctb

#### Python & Virtual Environments
toilet -f term -F border --gay "some python set up and virtual envs"
curl https://bootstrap.pypa.io/2.7/get-pip.py --output get-pip.py
sudo python get-pip.py
rm get-pip.py
sudo apt-get install -y python2.7
sudo apt-get install python3-pip -y
sudo apt-get install python-dev -y
sudo pip3 install virtualenv
sudo pip3 install virtualenvwrapper
export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
export VIRTUALENVWRAPPER_VIRTUALENV=/usr/local/bin/virtualenv
echo "export WORKON_HOME=$HOME/.virtualenv" >> ~/.zshrc
echo "export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3" >> ~/.zshrc
source /usr/local/bin/virtualenvwrapper.sh
source ~/.zshrc
cd ~/.virtualenv
virtualenv -p python3 python3
virtualenv -p python2 python2
echo -e "~#~ Alisas for activating python environments: py3act, py2act"
cat << EOF >> ~/.zshrc
alias py2act='source ~/.virtualenv/python2/bin/activate'
alias py3act='source ~/.virtualenv/python3/bin/activate'
EOF
echo -e ''
cd ~/
source ~/.zshrc


echo -e "${RED}============================================================${NC}"
echo -e "${RED}============================================================${NC}"
echo -e "${GREEN}==================Update the system=========================${NC}"
echo -e "${RED}============================================================${NC}"
echo -e "${RED}============================================================${NC}"
toilet -f term -F border --gay "apt-get update"
sudo apt-get update -y
toilet -f term -F border --gay "Go grab a coffee"
toilet -f term -F border --gay "this may take a moment..."
toilet -f term -F border --gay "we are running dist-upgrade now..."
sudo apt-get dist-upgrade -y
toilet -f term -F border --gay "phew...."

#### Lets install some additional progs and apps
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

toilet -f term -F border --gay "git"
sudo apt-get install git -y 2>/dev/null
toilet -f term -F border --gay "dbus-x11"
sudo apt-get install dbus-x11 -y 2>/dev/null
toilet -f term -F border --gay "linux-headers"
sudo apt-get install linux-headers-$(uname -r) -y 2>/dev/null
toilet -f term -F border --gay "hcxdumptool"
sudo apt-get install hcxdumptool -y 2>/dev/null
toilet -f term -F border --gay "hcxtools"
sudo apt-get install hcxtools -y 2>/dev/null
toilet -f term -F border --gay "dnsutils"
sudo apt-get install dnsutils -y 2>/dev/null
toilet -f term -F border --gay "exiftool"
sudo apt-get install  exiftool -y 2>/dev/null
toilet -f term -F border --gay "openvpn"
sudo apt-get install openvpn -y 2>/dev/null
toilet -f term -F border --gay "dialog"
sudo apt-get install dialog -y 2>/dev/null
toilet -f term -F border --gay "protonvpn"
sudo apt-get install protonvpn-cli -y 2>/dev/null
sudo apt-get update && sudo apt-get install protonvpn 2>/dev/null

echo -e "${RED}============================================================${NC}"
echo -e "${RED}============================================================${NC}"
echo -e "${GREEN}================ Update the system =========================${NC}"
echo -e "${RED}============================================================${NC}"
echo -e "${RED}============================================================${NC}"
sudo apt-get update -y
sudo apt-get autoremove -y

echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"

#### Lets install some additional progs and apps
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

toilet -f term -F border --gay "realtek-rtl88xxau-dkm"
sudo apt-get install -y realtek-rtl88xxau-dkms 2>/dev/null

toilet -f term -F border --gay "golang"
sudo apt-get install -y golang 2>/dev/null

toilet -f term -F border --gay "docker.io"
sudo apt-get install -y docker.io 2>/dev/null

toilet -f term -F border --gay "powershell"
sudo apt-get install -y powershell 2>/dev/null

toilet -f term -F border --gay " terminator"
sudo apt-get install -y  terminator 2>/dev/null

toilet -f term -F border --gay "python3-dev"
sudo apt-get install -y  python3-dev 2>/dev/null

toilet -f term -F border --gay "patator"
sudo apt-get install -y patator 2>/dev/null

toilet -f term -F border --gay "net-tools"
sudo apt-get install -y net-tools 2>/dev/null

toilet -f term -F border --gay "zmap"
sudo apt-get install -y zmap 2>/dev/null

toilet -f term -F border --gay "htop"
sudo apt-get install -y htop 2>/dev/null

toilet -f term -F border --gay "mosh"
sudo apt-get install -y mosh 2>/dev/null

toilet -f term -F border --gay "tmux"
sudo apt-get install -y tmux 2>/dev/null

toilet -f term -F border --gay "nfs-kernel-server"
sudo apt-get install -y nfs-kernel-server 2>/dev/null

toilet -f term -F border --gay "dnsmasq"
sudo apt-get install -y dnsmasq 2>/dev/null
 
toilet -f term -F border --gay "python tools"
sudo pip install --upgrade setuptools
python2 -m pip install pipenv
python3 -m pip install pipenv


toilet -f term -F border --gay "tmux config echo to file"
# default tmux config
cat <<EOF > ~/.tmux.conf
set -g mouse on
set -g history-limit 20000
EOF

echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}=================== setting up go ============================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

mkdir -p ~/.go
gopath_exp='export GOPATH="$HOME/.go"'
path_exp='export PATH="/usr/local/go/bin:$GOPATH/bin:$PATH"'
sed -i '/export GOPATH=.*/c\' ~/.profile
sed -i '/export PATH=.*GOPATH.*/c\' ~/.profile
echo $gopath_exp | tee -a "$HOME/.profile"
grep -q -F "$path_exp" "$HOME/.profile" || echo $path_exp | tee -a "$HOME/.profile"
. "$HOME/.profile"


printf ${GREEN}
figlet git clones
printf ${NC}
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}============================ - bettercap  ====================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

sudo apt-get install libnetfilter-queue-dev libpcap-dev libusb-1.0-0-dev 2>/dev/null
go get -v github.com/bettercap/bettercap

echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}============================ - SecLists  =====================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo apt-get install seclists -y 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}============================ - h8mail  =======================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/khast3x/h8mail $mytools/h8mail 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}=========================== - discover =======================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/leebaird/discover $mytools/discover 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - nmapautomator =====================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/21y4d/nmapAutomator.git $mytools/nmapAutomator 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - subbrute ==========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/TheRook/subbrute.git $mytools/subbrute 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - theHarvester ======================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/laramies/theHarvester.git $mytools/theHarvester 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - windows exploit suggester =========${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git $mytools/windows-exploit-suggester 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - nmap vulners ======================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/vulners 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - priv esc scripts ==================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git $mytools/priv-esc-scripts 2>/dev/null


echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - sublist3r =========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/aboul3la/Sublist3r.git $mytools/sublist3r 2>/dev/null



echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - sherlock ==========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/sherlock-project/sherlock.git $mytools/sherlock 2>/dev/null
python3 -m pip install -r $mytools/sherlock/requirements.txt



echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - windows reverse shell==============${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/Dhayalanb/windows-php-reverse-shell.git $mytools/windows-reverse-shell 2>/dev/null



echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - gobuster ==========================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/OJ/gobuster.git $mytools/gobuster 2>/dev/null



echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}================== Installing....... =========================${NC}"
echo -e "${GREEN}======================== - ffuf ==============================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
sudo git clone https://github.com/ffuf/ffuf.git $mytools/ffuf 2>/dev/null

figlet -c New Install Section
##### new additional tools
toilet -f term -F border --gay "git clone robots disallowed"
sudo git clone https://github.com/D4nk0St0rM/RobotsDisallowed.git /opt/mytools/robotsdisallowed 2>/dev/null

toilet -f term -F border --gay "git clone fimap"
sudo git clone https://github.com/kurobeats/fimap.git /opt/mytools/fimap 

toilet -f term -F border --gay "git clone dirsearch"
sudo git clone https://github.com/maurosoria/dirsearch.git /opt/mytools/dirsearch

toilet -f term -F border --gay "gimp photo editor"
sudo apt-get install gimp -y  2>/dev/null


echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}============= the cats are wearing the hats ==================${NC}"
echo -e "${GREEN}============== system update and clean up ====================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

sudo apt-get update -y 
sudo apt-get upgrade -y 
sudo apt-get autoremove -y




echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}                                                            ${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${GREEN}============= Reboot, grab a coffee ==========================${NC}"
echo -e "${GREEN}======= consider install paid licence items ==================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${RED}==============================================================${NC}"

printf ${GREEN}
figlet -c D4nk0St0rM
printf ${CYAN}
figlet -c spread l0v3 share kn0wl3dge
printf ${NC}
