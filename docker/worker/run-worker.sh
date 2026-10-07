#! /bin/sh


cat <<EOF

                                        :*#*                                    
                                    :****=:---:*                                
                                  *-===---*=----:#*                             
                                *:==----=---=:---.*.:                           
                               +===-----:=---=----:-.*                          
                              #====-------=-:*--:--*-.-                         
                             *=============:----------#                         
                             *=-==*=========--------=--*                        
                            *#*==++:---------::---..+++=.                       
                           *-+==%%%@@@@%%%+===+=:..:....:#                      
                            =#+=#####@@%##*%%%#%%%##%%%%###                     
                      ++++++  :*##****@::@%#***#%**@#@                          
                .++++ ++%##%%+++@#***#@-:.@.:@#@%+@.*                           
               +++++%%@%##%%%%%#@#***#*#@@@@##-+-::%*          @%@%             
              *++%%#%%%@%%#%##%#%%%#*****#%---------:%       @.==%    %%        
           ++++=%%###%%%@#%##%%%#%#@@##*%=#@%%%@=+---:     %.===@    +@=%       
          ++++%%%@##%%%%%@%#%###%%%%%%%#@=======@%@%--    .*====@    @==%       
         ++++%%%%%%@%#%%%%%%%%%@%%%@%%@@####@##     %*     *=====%%%@.==@       
          ++%%%%%%%%%@#%%%%@%%%%%%%%%%@%@**#%##%           @*===========@       
         ++:%%##%%%%%%@%%%%%%%%@%%%@%@%%@***##**            %*%=======+=        
        +++%#%#%%#%%%%%%%%%%@@######@@@@##****#*%           @++****%%           
       +++%%%%%#%%@@%%%%%@%##########%###*#******@         -:++++%              
       .++%#%#%%@#%%%@@%@#@############%#*******%@      %#@@+++-%               
         @@#%%%#%%%%%%%@############%###%@@##@##@##%   %###*%###@.              
        .++%%%#%@@%@%%%########%%%@%###############@%#@#@##%%%###%              
        +++%###%%%%%%@%%##########%%%#%%###########%%%%%%*@%####%               
        :++%#%##%%%%%@@%%%#########%%%######%%#####@%%%%-%%@%%#@                
         .++#%%%@@%%%%%@@%%%%%%#####%%%%##%######%%%%%%%+*%###@                 
            %%%%%%%%%@%%@@%%%#######%%%%%%%%%%%%%%@%%#@+#+**                    
            %%%%%%@=    @@%%%#####%@%%%%%%%%%%%%%-   %:=+++@                    
                          @%%%@%@%%%%%@%%%%%%@@@    @+++++%                     
                              @%%%%%%@@@@%%@%%      *+..#+                      
                               %%@%%     @@%@.      @#++*#                      
                               %*%         %+@                                  
                               @#%          *++                                 
                        .::::::##@:::::::@#=*+#=#%:=*=@                         
              .:::::::::::%=###@=*==-=@:#:%@+@@+#=@@@@=@::::::.                 
                ::::::::*@@@@::=#+:@@*@@:::::::::-%-@::::::::.                  
                           .-:::%@::::::::::::::::                              
 _____           _               ____  _ _       
|_   _|   _ _ __| | _____ _   _ | __ )(_) |_ ___ 
  | || | | | '__| |/ / _ \ | | ||  _ \| | __/ _ \\
  | || |_| | |  |   <  __/ |_| || |_) | | ||  __/
__|_| \__,_|_|  |_|\_\___|\__, ||____/|_|\__\___|
\ \      / /__  _ __| | __|___/ __                
 \ \ /\ / / _ \| '__| |/ / _ \ '__|               
  \ V  V / (_) | |  |   <  __/ |                  
   \_/\_/ \___/|_|  |_|\_\___|_|                             

EOF

export VALKEY_PASSWORD=$(cat /run/secrets/valkey_password)

# Configuration errors found while shipping are reported once per container;
# clearing the record lets this start say so again.
rm -rf "${TMPDIR:-/tmp}/turkeybite-config-errors"
export VALKEY_HOST=${VALKEY_HOST:-valkey}
export VALKEY_PORT=${VALKEY_PORT:-6379}
export VALKEY_DB=${VALKEY_DB:-0}
export TURKEYBITE_WORKER_PROCS=${TURKEYBITE_WORKER_PROCS:-2}

export TURKEYBITE_INDEX_SYNC_INTERVAL_SEC=${TURKEYBITE_INDEX_SYNC_INTERVAL_SEC:-300}

# Inside a container $(hostname) is the container id, which changes on every
# recreate. A consumer only recovers its own in-flight work on restart, so an
# unstable name strands whatever it had claimed in a processing list nobody will
# read again. Prefer an explicit prefix; fall back to the container id only so
# the thing still runs.
export TURKEYBITE_CONSUMER_PREFIX=${TURKEYBITE_CONSUMER_PREFIX:-$(hostname)}

# Check this worker's config.yaml before any consumer starts.
if ! python turkeybite check; then
    echo "Refusing to start the worker: fix config.yaml as above, then restart the container." >&2
    exit 1
fi

# No consumer in this container is running yet, so anything left in a
# processing list of a consumer named as tb-consume.template names them,
# <prefix>-NN, belongs to a previous incarnation. Only exactly that shape
# is swept, so a prefix that starts another host's is no risk to it.
python turkeybite queue-recover --prefix "${TURKEYBITE_CONSUMER_PREFIX}" || true

cat /etc/supervisor/conf.d/tb-consume.template | envsubst | tee /etc/supervisor/conf.d/tb-consume.conf
cat /etc/supervisor/conf.d/tb-index-sync.template | envsubst | tee /etc/supervisor/conf.d/tb-index-sync.conf
cat /etc/supervisor/conf.d/tb-psl.template | envsubst | tee /etc/supervisor/conf.d/tb-psl.conf
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf
