import threading
from qradar_siem_offenses_to_soar import main as offenses_to_soar_run
from reupload_failed_offenses_to_soar import main as retry_uploading_failed_offenses_run
from app_config import server_config

def send_offense_to_soar(server_config):
    '''Calls the main method for the send offenses to SOAR Python module, which runs in a separate thread.
    :param ServerConfig server_config: Configuration needed for the thread
    '''
    offenses_to_soar_run(server_config)

def retry_uploading_failed_offenses_to_soar(server_config):
    '''Calls the main method of the reupload failed offenses to SOAR Python module, which runs in a separate thread.
    
    :param ServerConfig server_config: Configuration needed for the thread
    '''
    retry_uploading_failed_offenses_run(server_config)

def main():
    '''Main method. Runs both threads (offenses and failed offenses) in daemon mode. '''
    t1 = threading.Thread(target=send_offense_to_soar, args=(server_config,), daemon=True)
    t2 = threading.Thread(target=retry_uploading_failed_offenses_to_soar , args=(server_config,), daemon=True)
    
    t1.start()
    t2.start()
    
    #List all threads currently running
    #print(threading.enumerate())

    try:
        while t1.is_alive() or t2.is_alive():
            t1.join(timeout=1)
            t2.join(timeout=1)
    except KeyboardInterrupt:
        print("Program interrupted! Exiting...")  


    # t1.start()

    # try:
    #     while t1.is_alive():
    #         t1.join(timeout=1)
    # except KeyboardInterrupt:
    #     print("Program interrupted! Exiting...")  

if __name__ == "__main__":
    main()