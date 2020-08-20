# Ubuntu Linux Install

This will probably work on most Debian based distros, but I've only tried on Ubuntu.

## Install Dependencies

```bash
sudo apt update;
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https;
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update;
sudo apt install dos2unix sed curl vim bind9 supervisor python3 python3-pip redis-server redis-tools elasticsearch kibana;
```

## Setup Redis

```bash
sudo apt update;
sudo apt install redis-server;
sudo vi /etc/redis/redis.conf;
# Set the `requirepass` option to a long password: https://stackoverflow.com/questions/7537905/redis-set-a-password-for-redis#:~:text=Make%20sure%20you%20choose%20something,in%20the%20config%20file%20mention
# Find `bind 127.0.0.1` and comment it out with a `#`.
# Add a new line: `bind 0.0.0.0` without the `. This will allow redis connections on all interfaces.
# For more on securing redis on Ubuntu: https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-redis-on-ubuntu-18-04
# save the config and restart redis
sudo systemctl restart redis;
sudo vi /etc/sysctl.conf;
# Add the following line:
# vm.overcommit_memory=1
# Then restart sysctl with:
sudo sysctl -p /etc/sysctl.conf;
```

## Setup Bind9

At a high level you'll want to configure this bind server to be a slave to your production authoritative DNS servers.
You'll want this bind server taking zone transfers from your master DNS servers so that it has a local copy of your network's DNS.
You'll also want this bind server forwarding requests to internet DNS servers (1.1.1.1, 8.8.8.8 and so on), NOT your main DNS servers that your clients use.
The reason for this is you'll create extra DNS traffic sent to Turkey Bite every time Turkey Bite looks up a host, which could be really really bad for your DNS servers.

[Click here to see my bind config example](bind9.md)

After configuring bin9 ensure the cache directory exists and restart bin9:

```bash
sudo mkdir -p /var/cache/bind;
sudo chown -r bind:bind /var/cache/bind;
sudo systemctl restart bind9;
```

## Setup Turkey Bite

```bash
# Get Turkey Bite
cd /opt
git clone https://github.com/MelonSmasher/TurkeyBite.git;
cd TurkeyBite;

# Copy the example config and whitelist
cp lists/whitelist.example.json lists/whitelist.json;
cp config.example.yaml config.yaml;

# Configure Turkey Bite
vi config.yaml;
# Make changes to the config as you need, ensure to set the same redis password as you did when setting up redis.
# You can also take a look at lists/whitelist.json if you'd like to whitelist domains from a specific context category.

# Install python libs
pip3 install -r requirements.txt;

# Download categorized domain lists and load them into redis:
./turkeybite hosts;

# Setup automatic downloads:
sudo crontab -e
# Add the following line: without the `#`
# 0 2 * * * cd /opt/turkey-bite && /usr/bin/python3 turkeybite hosts

# *** IMPORTANT *** If you download these lists at a frequency more often than 24 hours you will probably be banned by the list maintainers.
# You've been warned!

# Load the whitelist into redis
./turkeybite whitelist

# Run Turkey Bite in the foreground to ensure everything is working
python3 turkeybite run
```

## Setup data-streams

At this point Turkey Bite should be running, but has no incoming data analyze. Turkey Bite will analyze two types of data. It can inspect DNS packets forwarded by [Packetbeat](https://www.elastic.co/beats/packetbeat) and it can inspect web browser history from [Browserbeat](https://github.com/MelonSmasher/browserbeat).

### Setup Packetbeat

You'll need to install packetbeat on your DNS servers. The process for this varies based on your DNS server OS, but there are linux packages in the Elastic repos and [Chocolatey packages for Windows](https://chocolatey.org/packages/packetbeat).

Then configure it to [output data to your Turkey Bite Redis server](https://www.elastic.co/guide/en/beats/packetbeat/current/redis-output.html). The main options you'll want to configure is the `hosts`, `password`, and `key`. The host should be the hostname or IP of your Turkey Bite server. The password should be your redis password. The key should be the redis channel used in `config.yaml`, by default this is set to `turkeybite` in Turkey Bite's config.

### Setup Browserbeat

You'll need to deploy Browserbeat to any client's that you'd like to capture web browser history from. You can find [prebuilt packages on Github](https://github.com/MelonSmasher/browserbeat/releases) as well as a [Chocolatey package for Windows](https://chocolatey.org/packages/browserbeat).

Then configure it to [output data to your Turkey Bite Redis server](https://www.elastic.co/guide/en/beats/packetbeat/current/redis-output.html). The main options you'll want to configure is the `hosts`, `password`, and `key`. The host should be the hostname or IP of your Turkey Bite server. The password should be your redis password. The key should be the redis channel used in `config.yaml`, by default this is set to `turkeybite` in Turkey Bite's config.

If you are installing Browserbeat on a Windows client through Chocolatey the config file is located at: `%programdata%\chocolatey\lib\browserbeat\tools\browserbeat.yml` after changing the configuration restart the `browserbeat` service.

### Turkey Bite Service

After setting up some client's you should see Turkey Bite processing data in your foreground process. Stop the foreground process and do the following to run Turkey Bite as a service:

```bash
# Copy the service file to systemd
sudo cp support/turkey-bite.service /etc/systemd/system/turkey-bite.service;
sudo systemctl enable turkey-bite;
sudo systemctl start turkey-bite;
```

Next enable the Turkey Bite workers that process everything.

```bash
sudo systemctl stop supervisor;
sudo cp support/tb-worker.conf /etc/supervisor/conf.d/tb-worker.conf
# edit /etc/supervisor/conf.d/tb-worker.conf if needed
sudo systemctl restart supervisor;
```

### Viewing Turkey Bite

You should now be able to browse to the Kibana dashboard that you installed on your Turkey Bite server. For more info see [configuring Kibana](https://www.elastic.co/guide/en/kibana/current/settings.html) and [Access Kibana](https://www.elastic.co/guide/en/kibana/current/access.html).
