import requests
import time
import os
import json
from typing import Dict
from app_config import ServerConfig, failed_offenses_to_ibm_soar_retries_logger
from qradar_siem_offenses_to_soar import create_offense_in_soar

qradar_headers = {'SEC': None, 'Accept': 'application/json'} #Headers for QRadar API. Paritally obtained from config.ini file
failed_offenses_ids_list = [] #do not edit! Used to temporary store in memory the failed offenses IDs obtained from the file
config: ServerConfig = None

def load_failed_ids_from_file() -> str:
    """Load the ids of the failed offenses from the failed offenses file.
    
    :return: A string of the content in the file
    :rtype: Str
    :raises OSError,FileNotFoundError,ValueError: if an error occurs when opening/reading the file
    """
    if os.path.exists(config.failed_escalations_offenses_file):
        with open(config.failed_escalations_offenses_file, 'r') as file:
            return (file.read().strip())
    return None



def remove_offense_id_from_failed_offenses_file(offense_id:int) -> None:
    """Remove the offense Id from the failed offense file and from memory and rewrites the file with the failed missing offenses (if any)
    
    :param int offense_id: The ID of the offense to remove from the file and memory.
    :return: Nothing
    :rtype: None
    :raises OSError,FileNotFoundError,ValueError: if an error occurs when opening/editing the file
    """
    global failed_offenses_ids_list

    try:
        failed_offenses_ids_list.remove(offense_id)
    except:
        failed_offenses_to_ibm_soar_retries_logger.warn("Error removing failed offense ID from file. The offense ID did not exist on the file. Was the file manipulated by a user?.")
    
    failed_offenses_ids_as_string = [str(id) for id in failed_offenses_ids_list]
    comma_separated_string_of_failed_offense_ids = ",".join(failed_offenses_ids_as_string)

    with open(config.failed_processed_id_file, 'w') as file:
        if comma_separated_string_of_failed_offense_ids:
            file.write(comma_separated_string_of_failed_offense_ids)
        else:
            file.write("")

    failed_offenses_to_ibm_soar_retries_logger.info(f"Deleted succcesfully offense ID from the failed offenses file with ID {str(offense_id)}")



def get_offense(offense_id: int)-> Dict[any,any]: 
    """Retrieve an offense from QRADAR.

    :param int offense_id: The ID of the offense to get it's data from QRADAR.
    :return: The json response from obtaining the offense.
    :rtype: Dict[any,any]
    :raises HttpError: if an error occurs obtaining the offense info
    """
    global qradar_headers
    qradar_headers = qradar_headers.copy()
    qradar_headers["VERSION"] = "20.0"
    response = requests.get(config.qradar_url + "/" + str(offense_id), headers=qradar_headers, verify=False)
    response.raise_for_status()
    return response.json()



def process_offense(offense_id: int) -> None:
    """Process the next unprocessed offense and create an IBM SOAR Case for it.

    :param int offense_id: Receives the Offense ID of the offense to upload to IBM SOAR 
    :return: None
    :rtype: None
    """
    failed_offenses_to_ibm_soar_retries_logger.info("Processing and sending to IBM SOAR the old failed-to-upload offense_id to IBM SOAR with ID: " + str(offense_id))
    latest_offense = get_offense(offense_id)
    failed_offenses_to_ibm_soar_retries_logger.debug("Offense obtained from QRADAR SIEM: " + json.dumps(latest_offense))

    if latest_offense and latest_offense.get("status", None) == "OPEN":
        offense_id = latest_offense.get('id',None)
        failed_offenses_to_ibm_soar_retries_logger.info(f"Processing offense with ID. About to create case on IBM SOAR!: {str(offense_id)}")
        try:
            create_offense_in_soar(latest_offense)
            failed_offenses_to_ibm_soar_retries_logger.info(f"IBM SOAR case created succesfully for offense with ID: " + str(offense_id) + " . Proceeding to delete the ID of the offense from the failed offenses file.")
            remove_offense_id_from_failed_offenses_file(offense_id)
            pass
        except Exception as e:
            failed_offenses_to_ibm_soar_retries_logger.error(f"Error creating SOAR case on IBM SOAR for offense with id {offense_id} . Error: {str(e)}" )
    else:
        failed_offenses_to_ibm_soar_retries_logger.warning(f"Offense {offense_id} is closed or non-existent in QRADAR. Removing the offense ID from the file.")
        remove_offense_id_from_failed_offenses_file(offense_id)



def init_vars(passedconfig: ServerConfig):
    '''
    Initializates variables for the script

    :param int passedconfig: Configuration received from the config.ini file
    :return: None
    :rtype: None
    '''
    global config
    config = passedconfig
    global qradar_headers
    qradar_headers = {'SEC': config.qradar_api_key, 'Accept': 'application/json'}


def safe_convert_offense_id(id_str):
    try:
        return int(id_str)
    except ValueError:
        return None
    


def main(passedconfig: ServerConfig):
    
    init_vars(passedconfig)

    """Main loop to continuously check for failed offenses and try reuploading them to IBM SOAR."""
    while True:

        ids = load_failed_ids_from_file()

        if ids == None:
            ids = ''

        ids_as_string = ids.split(",")

        missing_failed_offenses_mssg = "No failed offense IDs to upload to IBM SOAR were found on the Failed IBM SOAR Offense Uploads File."
        if (ids_as_string and len(ids_as_string) > 0):
            global failed_offenses_ids_list

            # Use a set to avoid duplicates
            failed_offenses_ids_set = {
                safe_convert_offense_id(id_str) for id_str in ids_as_string if id_str.strip() != ""
            }

            # Filter out None values and convert back to a list
            failed_offenses_ids_list = [id for id in failed_offenses_ids_set if id is not None]
    
            if (len(failed_offenses_ids_list) > 0):
                for id in failed_offenses_ids_list:
                    try:
                        process_offense(id)
                    except Exception as e:
                        failed_offenses_to_ibm_soar_retries_logger.error(f"Error pulling and/or sending previously failed offense to IBM SOAR with ID: {e}. Advancing to next offense.")
            else:
                failed_offenses_to_ibm_soar_retries_logger.error(missing_failed_offenses_mssg)
        else:
            failed_offenses_to_ibm_soar_retries_logger.error(missing_failed_offenses_mssg)
        time.sleep(config.polling_rate_offenses_failure_reuploading)



if __name__ == "__main__":
    main()