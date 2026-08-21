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
export VALKEY_HOST=${VALKEY_HOST:-valkey}
export VALKEY_PORT=${VALKEY_PORT:-6379}
export VALKEY_DB=${VALKEY_DB:-0}
export TURKEYBITE_WORKER_PROCS=${TURKEYBITE_WORKER_PROCS:-2}
# rq.SimpleWorker runs jobs in the worker process instead of forking one per
# job, so a connection or an mmap opened once is actually reused. Job timeouts
# still work: SimpleWorker uses the same UnixSignalDeathPenalty, and perform_job
# still catches a raising job and fails it rather than taking the worker down.
# Set to rq.Worker to go back to fork-per-job.
export TURKEYBITE_WORKER_CLASS=${TURKEYBITE_WORKER_CLASS:-rq.SimpleWorker}

export TURKEYBITE_INDEX_SYNC_INTERVAL_SEC=${TURKEYBITE_INDEX_SYNC_INTERVAL_SEC:-300}

# Which ingestion path this worker runs.
#   rq       pub/sub into the core, RQ into these workers. The original path.
#   consume  claim from the durable Redis list, sieve, enrich, index, then
#            acknowledge. One process per event instead of two Redis hops, and
#            the acknowledgement after the flush is what makes batching safe.
export TURKEYBITE_PIPELINE=${TURKEYBITE_PIPELINE:-rq}
export TURKEYBITE_CONSUMER_PREFIX=${TURKEYBITE_CONSUMER_PREFIX:-$(hostname)}

if [ "${TURKEYBITE_PIPELINE}" = "consume" ]; then
    cat /etc/supervisor/conf.d/tb-consume.template | envsubst | tee /etc/supervisor/conf.d/tb-consume.conf
else
    cat /etc/supervisor/conf.d/tb-worker.template | envsubst | tee /etc/supervisor/conf.d/tb-worker.conf
fi
cat /etc/supervisor/conf.d/tb-index-sync.template | envsubst | tee /etc/supervisor/conf.d/tb-index-sync.conf
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf
