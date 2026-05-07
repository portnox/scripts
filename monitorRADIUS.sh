# the path to the localradfwtest.sh file
SCRIPT="./localradfwtest.sh"     
                                 
# Path to the mointoring log file
LOGFILE="./monitorRADIUS.log"      
                                                                       
# Add a timestamp header to the log                                    
echo "==================================================" >> "$LOGFILE"
echo "Run started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"         
echo "==================================================" >> "$LOGFILE"
                                                   
# Run the script and capture both stdout and stderr
"$SCRIPT" >> "$LOGFILE" 2>&1         
                                                                
# Add completion timestamp to the log                           
echo "Run completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"
echo "" >> "$LOGFILE"
