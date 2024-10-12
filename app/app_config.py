import base64
import configparser
import logging
from logging.handlers import RotatingFileHandler
from typing import List, TypedDict

class SOARCustomerDetails(TypedDict):
    '''Class for typing custom details obtained from the config.ini'''
    soar_api_key_auth: str
    soar_org_id: str
    siem_org_id:str
    
class ServerConfig:
    '''Class for app configuration. Contains main configuration variables that are used for the app.'''
    def __init__(self):
        self.qradar_url:str = None
        self.soar_url: str = None
        self.qradar_api_key:str = None
        self.failed_escalations_offenses_file:str = None
        self.last_escalated_offense_file:str = None
        self.logging_level:str = None
        self.cli_logging_enabled:bool = None
        self.polling_rate_new_offenses_checking:int = None
        self.polling_rate_offenses_failure_reuploading:int = None
        self.customer_configurations: dict[str,SOARCustomerDetails] = {}
        self.customer_orgs: list[str] = []

def is_valid_section(section_data):
    """Check if the section has valid values for soar_api_id, soar_api_key, soar_org_id and siem_org_id."""
    try:
        soar_api_id = section_data.get('soar_api_id')
        soar_api_key = section_data.get('soar_api_key')
        
        try:
            soar_org_id = int(section_data.get('soar_org_id'))  # Ensure it's an integer
        except Exception:
            soar_org_id = -1

        try:
            siem_org_id = int(section_data.get('siem_org_id'))  # Ensure it's an integer
        except Exception:
            siem_org_id = -1

        # Validate that soar_api_id and soar_api_key are non-empty strings
        # and soar_org_id and siem_org_id is a positive integer.
        if isinstance(soar_api_id,str) and soar_api_id.strip() != "" and isinstance(soar_api_key,str) and \
            soar_api_key.strip() != "" and isinstance(soar_org_id, int) and soar_org_id >= 0 and isinstance(siem_org_id, int) and siem_org_id >= 0:
            #return {"soar_api_id": soar_api_id, "soar_api_key":soar_api_key, "soar_org_id" : soar_org_id }
            return True
        else:
            print("Not a valid section data")
    except (ValueError, configparser.NoOptionError):
        print("Exception with section")
        return False  # Return false if any required option is missing or invalid
    
    return False

def generate_basic_auth(api_id, api_key):
    # Combine the API ID and API key with a colon
    credentials = f"{api_id}:{api_key}"
    # Encode the credentials in Base64
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    # Return the Authorization header value
    return f"{encoded_credentials}"

def filter_valid_sections(config):

    valid_sections = {}

    sections: List[str] = config.sections()
    # Iterate over all sections
    for section in sections:
        customer_name = section.replace("Customer_", "", 1)
        # Filter sections that start with 'Customer_'
        if section.startswith('Customer_'):
            if bool(customer_name.strip()):
                customer_name = section.replace("Customer_", "", 1)
                section_data = dict(config.items(section))           
                # Check if the section is valid
                if is_valid_section(section_data):
                    valid_sections[section] = {
                        "soar_org_id": section_data.get("soar_org_id"),
                        "siem_org_id": section_data.get("siem_org_id"),
                        "soar_api_key_auth": generate_basic_auth(section_data.get("soar_api_id"), section_data.get("soar_api_key"))
                    }
                else:
                    print(f"Section {section} had invalid data. Customer section will be ommited and offenses might not be escalated for such customer.")
            else:
                print(f"Skipping section {section} due not being a Customer_ section or having an empty customer name.")

    return valid_sections

def get_customer_domains(customer_configs:dict[str,dict[any]]):
    customer_names = []
    if customer_configs:
        pass
        for key in customer_configs.keys():
            print(key)
            customer_name = key.split("Customer_",1)[1].strip()
            print(customer_name)
            try:
                found = customer_names.index(customer_name,0)
            except ValueError:
                customer_names.append(customer_name)
        return customer_names
    else:
        return []

def get_logging_level(level:str):
    '''Maps the logging level string to a corresponding logging level integer valule. If an invalid one is passed, will default to INFO.

    Accepted levels:

    - DEBUG/debug: 10
    - INFO/info:  20
    - WARNING/warning: 30
    - ERROR/error: 40
    - CRITICAL/critical: 50
    
    :param: str level: Level of logging to set based on the level received as an string.
    :return: Level of the logging to be used on the files.
    :rtype: int 
    '''
    
    if level is None:
        level = ''
    else:
        level = level.strip().upper()

    log_level_mapping = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }

    # Set the logging level for the app logger based on the config value
    if level in log_level_mapping:
        return log_level_mapping[level]
    else:
        print(f"An invalid logging level has been retrieved from the config.ini file. Using default level INFO.")
        return logging.INFO

def init_server_config():
    '''Initializes ServerConfig object to be used by app modules by using the config.ini file and the configparser module.
    
    :return: ServerConfig object with the configuration for the app
    :rtype: ServerConfig'''
    #Read the configuration file
    print('[QRadar2IBM_SOAR_automated_escalation] Building App configparser...')
    config = configparser.ConfigParser()
    print('[QRadar2IBM_SOAR_automated_escalation] Reading config.ini file...')
    config.read('config.ini')
    print('[QRadar2IBM_SOAR_automated_escalation] Config.ini file read succesfully!...')

    # Create an instance of server_config
    server_config = ServerConfig()

    # Retrieve the variables and assign them to server_config
    server_config.qradar_url = config.get('MainConfig', 'qradar_url')
    server_config.soar_url = config.get("MainConfig", "soar_url")
    server_config.qradar_api_key = config.get('MainConfig', 'qradar_api_key')
    server_config.failed_escalations_offenses_file = config.get('MainConfig', 'failed_escalations_offenses_file')
    server_config.last_escalated_offense_file = config.get('MainConfig', 'last_escalated_offense_file')

    config_level = config.get('Logging','logging_level')
    server_config.logging_level = get_logging_level(config_level)
    # Get the 'enabled CLI logging' value from the config, defaulting to 'True'
    enabled_value = config.get('Logging', 'cli_logging_enabled', fallback='True')
    
    # Convert the value to a boolean
    try:
        cli_logs_enabled = (enabled_value is not None and enabled_value.lower() == 'true')
        print(cli_logs_enabled)
    except ValueError as e:
        print(e)
        # Handle invalid boolean values
        cli_logs_enabled = True  # Default to True if the value is invalid

    server_config.cli_logging_enabled = cli_logs_enabled

    try:
        server_config.polling_rate_new_offenses_checking = config.getint("OffensesPollingRate",'polling_rate_new_offenses_checking')
        if (server_config.polling_rate_new_offenses_checking is None or server_config.polling_rate_new_offenses_checking < 1):
            print(f"[QRadar2IBM_SOAR_automated_escalation] WARNING New offenses to IBM SOAR polling time in seconds is misconfigured. Should be an integer value bigger or equal than 1. Defaulting to 5 (seconds)")
            server_config.polling_rate_new_offenses_checking = 5
    except:
        print(f"[QRadar2IBM_SOAR_automated_escalation] WARNING New offenses to IBM SOAR polling time in seconds is misconfigured. Should be an integer value from 5 to 3600. Defaulting to 15 (seconds)")
        server_config.polling_rate_new_offenses_checking = 5

    try:
        server_config.polling_rate_offenses_failure_reuploading = config.getint("OffensesPollingRate",'polling_rate_offenses_failure_reuploading')
        if (server_config.polling_rate_offenses_failure_reuploading is None or server_config.polling_rate_offenses_failure_reuploading < 1):
            print(f"[QRadar2IBM_SOAR_automated_escalation] WARNING Reuploading failed offenses to IBM SOAR polling time in seconds is misconfigured. Should be an integer value bigger or equal than 1. Defaulting to 1800 (seconds)")
            server_config.polling_rate_offenses_failure_reuploading = 1800
    except:
        print(f"[QRadar2IBM_SOAR_automated_escalation]  WARNING Reuploading failed offenses to IBM SOAR polling time in seconds is misconfigured. Should be an integer value from 5 to 3600. Defaulting to 15 (seconds)")
        server_config.polling_rate_offenses_failure_reuploading = 1800

    #Get customer config and customer domains
    server_config.customer_configurations = filter_valid_sections(config)
    server_config.customer_orgs = get_customer_domains(server_config.customer_configurations)


    return server_config

server_config = init_server_config()

########################################LOGGERS CONFIGURATION!!!!!##################################################

def get_formatter_for_logger(formatter_identifier:str = None):
    '''Generates a formatter for a handler inside a logger. Pass a formatter identifier to identify the handler in a unique way
    
    :param str formatter_identifier: Identifier to add at the start of the formatted log
    :return: Formatter to be used when generating logs in the file
    :rtype: Formatter
    '''
    if formatter_identifier:
        formatter = logging.Formatter(formatter_identifier  + ' %(asctime)s %(levelname)s: %(message)s [in %(funcName)s():%(lineno)d] [%(filename)s]')
    else:
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    return formatter

def configure_logger(logger_to_config:logging.Logger, handler_formatter_identifier:str,log_file_name:str):
    '''
    Configures a logger. Pass a Logger Instance, an identifier to use on the handler formatter and the file name where to store the logs.
    
    :param  Logger logger_to_config: Logger to configure.
    :param str handler_formatter_identifier:  Handler formatter identifier to add in the logger configured. get_formatter_for_logger(formatter) is called to configure the format of the logs for the affected logger.
    :param str log_file_name: Log file to use to store the logs for the configured logger.
    :return: None
    :rtype: None
    '''
    handler_formatter = get_formatter_for_logger(handler_formatter_identifier)
    #By default files will have a max of 15MB and rotate when reached. 3 historical rotated files will be stored.
    handler = RotatingFileHandler('logs/' + log_file_name, maxBytes=15728640, backupCount=3)
    handler.setLevel(server_config.logging_level)
    handler.setFormatter(handler_formatter)
    logger_to_config.addHandler(handler)

    if (server_config.cli_logging_enabled == True):
        print("Logging seems to be enabled...")
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(server_config.logging_level)
        stream_handler.setFormatter(handler_formatter)
        logger_to_config.addHandler(stream_handler)
    else:
        print("You seem to have disabled CLI logging. Most logs will no longer appear on the CLI. Check log files for log information.")
    #Test handler
    logger_to_config.debug(f'{handler_formatter_identifier} is properly configured and working.')

# Defined loggers for different server processes
app_bootstrap_logger = logging.getLogger("app_bootstraping")
offenses_to_ibm_soar_logger = logging.getLogger("offenses_to_ibm_soar_logger")
failed_offenses_to_ibm_soar_retries_logger = logging.getLogger("failed_offenses_to_ibm_soar")

logging.getLogger().setLevel(server_config.logging_level)

configure_logger(app_bootstrap_logger, '[app_bootstrap_logger]','app_bootstrap.log')
configure_logger(offenses_to_ibm_soar_logger, '[offenses_to_ibm_soar_logger]','offenses_to_ibm_soar_logger.log')
configure_logger(failed_offenses_to_ibm_soar_retries_logger, '[failed_offenses_to_ibm_soar_retries_logger]','failed_offenses_to_ibm_soar.log')

###FINAL MESSAGE:

app_bootstrap_logger.critical(f'''
QRADAR 2 IBM SOAR Integration                                                                                                                                                                                                                                                             
Developed by cvivasf
''')
app_bootstrap_logger.critical(f"#######################################################################")
app_bootstrap_logger.critical('[QRadar2IBM_SOAR_automated_escalation] Configuration of QRADAR 2 IBM SOAR Application:')
app_bootstrap_logger.critical(f"    Current LOG LEVEL: {server_config.logging_level}")
app_bootstrap_logger.critical(f"    CLI Logging enabled?: {server_config.cli_logging_enabled}")
app_bootstrap_logger.critical(f"    QRADAR URL: {server_config.qradar_url}")
app_bootstrap_logger.critical(f"    SOAR URL: {server_config.soar_url}")
app_bootstrap_logger.critical(f"    Last Escalated Offense ID file location: {server_config.last_escalated_offense_file}")
app_bootstrap_logger.critical(f"    Failed Escalated Offense IDs file location: {server_config.failed_escalations_offenses_file}")
app_bootstrap_logger.critical(f"    Time to wait for polling new offenses from QRADAR and sending them to IBM SOAR: {server_config.polling_rate_new_offenses_checking}")
app_bootstrap_logger.critical(f"    Time to wait for sending new failed offenses from QRADAR to IBM SOAR: {server_config.polling_rate_offenses_failure_reuploading}")
app_bootstrap_logger.critical(f"    SIEM/SOAR Organization configurations: {server_config.customer_configurations}")
app_bootstrap_logger.critical(f"    SIEM Organization Names properly parsed: {server_config.customer_orgs}")
app_bootstrap_logger.critical(f"Integrating QRADAR Offenses with IBM SOAR Now!...")
app_bootstrap_logger.critical(f"#######################################################################")