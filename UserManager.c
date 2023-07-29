#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>
#include ".\lib\cryptography.h"

/*
    Known problems:
        - Program crashes when entering a new password, but only if a password reset request was sent.
        - When changing a user's password, the password manager does not change the encryption.
        - The current password will not be requested if a password reset request has been sent.
        - (A second user is also added to the administrator group).
    Features:
        General:
            - Create User
            - Delete User
            - Manage Users
            - User Administration
            - Permission Management
        Security:
            - Password Generator
            - Hashing Algorithms (currently: sha256, md5) are used to make passwords unreadable.
            - Password management (encryption: Zero Knowlage principle)
            - User is warned if someone has entered the password incorrectly 3 times the next time the user logs in.
        TODO Lists:
            - Warning when the deadline of a todo list is exceeded or about to expire.
            - Create and Manage TODO Lists
        Other
            - Auto Login
            - Analytics

    Todo:
        - Share todos
        - Password may expire
*/

#define MAX_USERNAME 30          // Maximum length of the user name
#define MAX_EMAIL 40             // Maximum length of e-mail address
#define MAX_PHONENUMBER 30       // Maximum length of phone number
#define MAX_PASSWORD 200         // Maximum length of the password
#define MAX_FIRSTNAME 30         // Maximum length of the first name
#define MAX_LASTNAME 30          // Maximum length of last name
#define MAX_ANSPRACHE 10         // Maximum length of the address
#define MAX_UUID 37              // Maximum length of the UUID(Unique Identifier)
#define MAX_USER_FILE_SIZE 10000 // Maximum size of the user file.
#define MAX_USERS 30             // Maximum number of users.

#define MAX_HASH 65 // Maximum length of hashcode.
#define MAX_DATE 12

#define MAX_GROUPS 30              // Maximum number of groups
#define MAX_GROUP_NAME 30          // Maximum length of the group name
#define MAX_GROUP_FILE_SIZE 10000  // Maximum size of the group file
#define MAX_PERMISSIONS 10         // Maximum number of permissions a group may contain
#define PERMISSION_ALL 0           // Numeric value for all permissions
#define PERMISSION_MANAGE_USERS 1  // Numeric value for the permission to manage users
#define PERMISSION_MANAGE_GROUPS 2 // Numeric value for the permission to manage groups
#define PERMISSION_ANALYTICS 3     // Numeric value for the permission to read the analytics
#define PERMISSION_CONFIGURATION 4 // Numeric value for the permission to change the program settings

#define MAX_ANALYTICS_FILE_SIZE 10000 // Maximum size of analytics file
#define MAX_ANALYTICS 10              // Maximum number of analytics files
#define ANALYTICS_CREATE_USER 0       // Numeric value for the number of created users
#define ANALYTICS_DELETE_USER 1       // Numeric value for the number of deleted users
#define ANALYTICS_CREATE_GROUP 2      // Numeric value for the number of created groups
#define ANALYTICS_DELETE_GROUP 3      // Numeric value for the number of deleted groups
#define ANALYTICS_LOGINS 4            // Numeric value for the number of logins
#define ANALYTICS_CREATE_TODO 5       // Numeric value for the number of created TODO lists

#define MAX_CONFIG_FILE_SIZE 10000 // Maximum size of the configuration file
#define MAX_CONFIG 10              // Maximum number of settings
#define MAX_CONFIG_LENGTH 100      // Maximum length of settings

#define MAX_TODO_FILE_SIZE 10000  // Maximum size of the TODO list file
#define MAX_TODOS 100             // Maximum number of TODO lists
#define MAX_TODO_ENTRY_LENGTH 20  // Maximum length of the TODO entries
#define MAX_TODO_NAME 30          // Maximum length of the name for a TODO list
#define MAX_TODO_DESCRIPTION 300  // Maximum length of the description for a TODO list
#define MAX_TODO_ENTRIES 80       // Maximum number of entries for a TODO list
#define MAX_TODO_DEATHLINE 60     // Maximum length of the TODO list deadline
#define MAX_TODO_SHARE_ACCOUNTS 5 // Maximum number of accounts you can share your TODO list with
#define MAX_TODO_SEARCH_STRING 20

#define MAX_PM_FILE_SIZE 10000
#define MAX_PM_PES 100
#define MAX_PM_PE_NAME 30
#define MAX_PM_PE_EMAIL 30
#define MAX_PM_PE_PASSWORD 200

// Contains the data for a group
struct GroupData
{
    char uuid[MAX_UUID];
    int id;
    char name[MAX_GROUP_NAME];

    int permissions[MAX_PERMISSIONS];
};
// Contains the data for the user
struct UserData
{
    char uuid[37];
    char username[MAX_USERNAME];
    char email[MAX_EMAIL];
    char phonenumber[MAX_PHONENUMBER];
    char password[MAX_HASH];
    char firstname[MAX_FIRSTNAME];
    char lastname[MAX_LASTNAME];
    char salutation[MAX_ANSPRACHE];
    struct GroupData group;
    int autologin;
    int login_warning;
    int reset_password;
};
// Contains the data for the TODO list
struct TodoData
{
    struct UserData user;
    int id;
    int entry_count;
    char uuid[MAX_UUID];
    char name[MAX_TODO_NAME];
    char description[MAX_TODO_DESCRIPTION];
    char deadline[MAX_TODO_DEATHLINE];
    char entries[MAX_TODO_ENTRIES][MAX_TODO_ENTRY_LENGTH];
};
// Contains the configuration
struct ConfigData
{
    char autologin[MAX_CONFIG_LENGTH];
    int running_retry_passwort_timeout;
    int running_passwort_trys;
    int retry_passwort_timeout;
    int password_trys;
    char password_deadline[MAX_DATE];
};
// Contains the data for an entry in the password manager
struct PasswordEntry
{
    char uuid[MAX_UUID];
    char name[MAX_PM_PE_NAME];
    char email[MAX_PM_PE_EMAIL];
    char password[MAX_PM_PE_PASSWORD];
};

int showMenu();   // Displays the main menu
void showLogin(); // Displays the login menu
void showNewUserScreen(char *localusername, char *email, char *phonenumber, char *localpassword, char *localfirstname, char *locallastname, char *localansprache);
void showNewUserMenu();         // Show the menu for creating your new user
void showOptions();             // Show the menu for the program settings
void showUserOptions();         // Show the menu for the user settings
void showUserManager();         // Shows the user management menu
void showGroupManager();        // Shows the group management menu
void showEditGroupMenu(int id); // Shows the menu for editing a group
void showEditUserMenu();        // Shows the second menu for user settings
void showTodoList();            // Shows the menu for editing TODO lists
void showCreateTodo();          // Shows the menu for creating a TODO list
void showEditTodo();            // Shows the menu for editing a TODO list
void showDeleteTodo();          // Shows the menu for deleting a TODO list
void showPasswordManager();     // Shows the menu for the password manager

void showPasswordGenerator(char *password, int length);                                                                                                               // Shows the password generator menu
void generatePassword(int capitalletters, int noncapitalletters, int specialletters, int amount, char *password);                                                     // Generates a password
void createUser(char *localusername, char *localemail, char *localphonenumber, char *localpassword, char *localfirstname, char *locallastname, char *localansprache); // Creates a user
int UserExists(char *username);                                                                                                                                       // Checks if a user with the given username exists
int getUsers(struct UserData *users);                                                                                                                                 // Stores all existing users into an array of type USERDATA
int getUserByUUID(char *uuid, struct UserData *user);                                                                                                                 // Stores a user with a given UUID into a variable of type USERDATA
int getUserByName(char *username, struct UserData *user);                                                                                                             // Stores a user into a variable of type USERDATA which has a given username
int changeUser(char *uuid, char *mode);                                                                                                                               // Changes the data of a user with a given UUID using the mode
int deleteUser(char *uuid);                                                                                                                                           // Delete a user with a given UUID
int Login(char *localusername, char *localpassword);                                                                                                                  // User will be logged in with the account containing the username and password
int AutoLogin();                                                                                                                                                      // User will be logged in automatically if he has set it
int Logout();                                                                                                                                                         // Logged in user will be logged out
int checkPassword(char *pwd, char *pwdhash);                                                                                                                          // A password string is compared with a password hash
int UserExists(char *username);                                                                                                                                       // Returns true if a user with a given username exists
void saveUser(struct UserData user);                                                                                                                                  // Saves a specified user

void createGroup(char *name, int *permissions, int logging); // Create a group by name and permissions
void deleteGroup(int id);                                    // Delete a group based on the group ID
int getGroups(struct GroupData *groups);                     // Stores all existing groups into an array of type GROUPDATA
int GroupExists(char *groupname);                            // Returns true if a group with a given group name exists
int getGroupByID(int id, struct GroupData *group);           // Stores a specific group by its ID into a variable of type GROUPDATA
int hasPermission(char *uuid, int perm);                     // Returns true if the user has a given permission

int getAnalytics(int *analytics);  // Stores all analytics into an array of type integer
void addAnalytic(int key);         // Increment an analysis by 1
void setAnalytics(int *analytics); //
void showAnalytics();              // Displays the analyses
void resetAnalytics();             // Resets all analytics

void clearScreen();                            // Clears the console
void init();                                   // Creates the necessary files and ensures that no errors occur
void writeFile(char *str, char *path);         // Writes a string to a file
void appendFile(char *str, char *path);        // Append a string to a file
void readFile(char *str, char *path, int len); // Reads a string from a file
int fexists(const char *fileName);             // Checks whether a file exists
int fcreate(const char *fileName);             // Creates a file
int fdelete(const char *fileName);             // Deletes a file
int folderExists(const char *folderName);      // Checks if a folder exists

int checkPasswordStrength(char *password); // Checks the strength of the password
int password_common(char *password);       // Checks if a default password is used
void generate_uuid(char *uuid_str);        // Create a UUID(Unique Identifier)
void initRandom();                         // Initiates the rand() function
int random(int max, int min);              // Generate a random number

void createTodo(char *name, char *description, char *deadline);                  // Creates a TODO list
void deleteTodo(char *uuid);                                                     // Delete a TODO list
int changeTodo(char *uuid, char *mode);                                          // Changes a TODO list depending on what the string 'mode' contains
int getTodos(struct TodoData *todos);                                            // Store all existing TODO lists into an array TODODATA
int getTodosByUserUUID(char *uuid, struct TodoData *todos);                      // Store the TODO list belonging to a specific user into a variable of type TODODATA
int getTodoByUUID(char *uuid, struct TodoData *todo);                            // Saves the TODO list owned by a specific UUID into a variable of type TODODATA
int getTodoByID(int id, struct TodoData *todo);                                  // Saves the TODO list with a given ID into a variable of type TODODATA
void saveTodo(struct TodoData todo, int index);                                  // Saves changes in a TODO list to the file
int todoExists(char *name);                                                      // Checks if a TODO list with a given name exists
void checkTodoDeadlines(struct TodoData *todos, int todo_amount, int *daysleft); // Checks if the current day is close to the deadline of a TODO list.

int getPasswordEntries(struct PasswordEntry *pes); // Stores the password entries of a user into an array of type PASSWORDENTRY
void addPasswordEntry();                           // Adds a password entry to the password manager
void deletePasswordEntry();                        // Delete a password entry from the password manager
void editPasswordEntry();                          // Change a password entry from the password manager

void setConfig(struct ConfigData config); // Sets a configuration
int getConfig(struct ConfigData *config); // Stores a configuration into a variable of type CONFIGDATA
void resetConfig();                       // Resets the configuration

void zn_encrypt(const char *rawdata, char *password, char *data); // Encrypts a string with a zero-knowledge algorithm
void zn_decrypt(const char *data, char *password, char *rawdata); // Decrypts a string with a zero-knowledge algorithm

void getDate(char *date);
int checkDeadline(char *deadline);
int getPassword(char *message, char *password, int password_len); // Get a password from the user
int validate_format(char *str);                                   // Checks whether a string has a given format
void char_to_str(char ch, char *str);                             // Convert a char to a string
void str_trim(char *array);                                       // Removes the \n at the end of a string
int str_split(char *str, char *delimiter, char **array);          // Splits a string at a given delimiter and stores the result in a string array
void showProgress(int progress, int max);                         // Displays a progress bar

int validate_phone_number(char *phone_number); // Validates the format of a string to the format of an email address
int validate_email(char *email);               // Validates the format of a string to the format of a phone number
int running = 0;

struct UserData current_user;
int logged_in = 0;
char folder[50];
char config_file[50];
char users_file[50];
char groups_file[50];
char passwordsfolder[50];
char standart_passwords_file[50];
char analytics_file[50];
char todo_file[50];
char password_manager_folder[50];

int main()
{
    initRandom();
    init();
    AutoLogin();
    int error = showMenu();
    clearScreen();
    return error;
}

int showMenu()
{
    running = 1;
    do
    {
        clearScreen();
        struct TodoData todos[MAX_TODOS];
        struct TodoData todos2[MAX_TODOS];
        int todo_amount = getTodos(todos);
        getTodos(todos2);
        int daysleft[MAX_TODOS];
        checkTodoDeadlines(todos, todo_amount, daysleft);
        for (int i = 0; i < todo_amount; i++)
        {
            if (strcmp(todos[i].deadline, "null") != 0)
            {
                int days_left = daysleft[i];
                struct TodoData todo = todos2[i];

                if (days_left > 0)
                {
                    printf("[%s] | %s -> Waehre schon vor %d Tagen zu erledigen gewesen!\n", todo.name, todo.description, days_left);
                }
                else if (days_left < 0 && days_left > -7)
                {
                    printf("[%s] | %s -> In %d Tagen zu erledigen!\n", todo.name, todo.description, days_left * -1);
                }
                else if (days_left == 0)
                {
                    char *deadline_split[MAX_TODO_DEATHLINE];
                    char *time_split[10];
                    str_split(todo.deadline, "-", deadline_split);
                    str_split(deadline_split[1], ".", time_split);
                    int hours = atoi(time_split[0]);
                    int minutes = atoi(time_split[1]);
                    printf("[%s] | %s -> Heute bis %d:%d zu erledigen.\n", todo.name, todo.description, hours, minutes);
                }
            }
        }

        printf("-------------------------------------------\n");
        int i = 0;
        printf("[%d] Schliesen\n", i);
        i++;
        if (!logged_in)
        {
            printf("[%d] Login\n", i);
            i++;
        }
        else
        {
            printf("[%d] Logout\n", i);
            i++;
        }
        if (!logged_in)
        {
            printf("[%d] Neuer Benutzer\n", i);
            i++;
        }
        if (logged_in)
        {
            printf("[%d] TODO Liste\n", i);
            i++;
        }
        if (logged_in)
        {
            printf("[%d] Passwortverwaltung\n", i);
            i++;
        }
        if (logged_in)
        {
            printf("[%d] Profil\n", i);
            i++;
        }
        if (logged_in && (hasPermission(current_user.uuid, PERMISSION_MANAGE_USERS) || hasPermission(current_user.uuid, PERMISSION_MANAGE_GROUPS) || hasPermission(current_user.uuid, PERMISSION_ANALYTICS)))
        {
            printf("\nAdministrations Werkzeuge:\n");
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_MANAGE_USERS))
        {
            printf("[%d] Benutzer verwalten\n", i);
            i++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_MANAGE_GROUPS))
        {
            printf("[%d] Gruppen verwalten\n", i);
            i++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_ANALYTICS))
        {
            printf("[%d] Analytics anzeigen\n", i);
            i++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_CONFIGURATION))
        {
            printf("[%d] Einstellungen\n", i);
            i++;
        }
        printf("-------------------------------------------\n");

        fflush(stdin);
        printf("# ");
        int in = getch();

        int index = 48;
        if ((int)in == index)
        {
            return 0;
        }
        index++;
        if (!logged_in)
        {
            if ((int)in == index)
            {
                showLogin();
            }
            index++;
            if ((int)in == index)
            {
                showNewUserMenu();
            }
            index++;
        }
        else
        {
            if ((int)in == index)
            {
                Logout();
            }
            index++;
        }
        if (logged_in)
        {
            if ((int)in == index)
            {
                showTodoList();
            }
            index++;
            if ((int)in == index)
            {
                showPasswordManager();
            }
            index++;
            if ((int)in == index)
            {
                showUserOptions();
            }
            index++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_MANAGE_USERS))
        {
            if ((int)in == index)
            {
                showUserManager();
            }
            index++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_MANAGE_GROUPS))
        {
            if ((int)in == index)
            {
                showGroupManager();
            }
            index++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_ANALYTICS))
        {
            if ((int)in == index)
            {
                showAnalytics();
            }
            index++;
        }
        if (logged_in && hasPermission(current_user.uuid, PERMISSION_CONFIGURATION))
        {
            if ((int)in == index)
            {
                showOptions();
            }
            index++;
        }
    } while (running);
    return 1;
}

void showLogin()
{
    clearScreen(); // Konsole wird geleert

    int error = 1;
    char localusername[MAX_USERNAME];
    struct UserData users[MAX_USERS];
    struct UserData user;
    struct ConfigData config;
    getConfig(&config);
    int amount = getUsers(users); // Alle exestierenden Benutzer werden in ein Array vom Typ USERDATA gespeichert.
    if (amount > 0)
    {
        do
        {
            if (!error)
            {
                printf("This user does not exist, please enter another user name: ");
            }
            else
            {
                printf("Please enter the Username: ");
            }
            fflush(stdin);
            fgets(localusername, MAX_USERNAME, stdin); // Benutzername wird eingelesen

            error = UserExists(localusername); // Es wird ueberprueft ob der angegebene Benutzer exestiert
        } while (!error);                      // Diese Schleife wird so lange laufen, bis es keinen Fehler mehr giebt
        int index = getUserByName(localusername, &user);

        error = 1;                           // Die Fehler variable wird inizialisiert
        int pwd_trys = config.password_trys; // pwd_trys wird inizialisiert
        do
        {
            char localpassword[MAX_PASSWORD];
            char message[100];
            if (error == -1)
            {
                char str[2];
                strcpy(message, "The password is wrong, you still have ");
                sprintf(str, "%d", pwd_trys); // Der Integer pwd_trys wird in einen String umgewandelt
                strcat(message, str);
                strcat(message, " trys");
                pwd_trys--; // pwd_trys wird dezimiert
            }
            else
            {
                strcpy(message, "Please enter your password");
            }
            fflush(stdin);                                                    // Loeschen des STDIN Streams
            int pwderror = getPassword(message, localpassword, MAX_PASSWORD); // Eingabe des Passwortes
            if (pwderror == -1)
            {
                return; // Wenn das Eingeben des Passwortes abgebrochen wurde
            }
            else
            {
                error = Login(localusername, localpassword); // Benutzer wird angemeldet
                if (!error)
                {
                    if (user.reset_password)
                    {
                        int input_empty = 0;
                        char localpassword[MAX_PASSWORD];
                        char confpassword[MAX_PASSWORD];
                        char passwordhash[MAX_HASH];

                        printf("You have to choose a new password, because the old one expired!");
                        char conf;
                        do
                        {
                            printf("\nDo you want to use the Password Generator[Y/N]: ");
                            conf = getchar();
                        } while (conf != 'Y' && conf != 'N');

                        if (conf == 'N')
                        {
                            int pwd_same = 0;
                            do
                            {
                                char message[100];
                                if (input_empty)
                                {
                                    strcpy(message, "The new password must not be empty");
                                }
                                else if (pwd_same)
                                {
                                    strcpy(message, "The new password must not be identical to the previous password");
                                }
                                else
                                {
                                    strcpy(message, "Enter your new Password");
                                }
                                if (getPassword(message, localpassword, MAX_PASSWORD) == -1)
                                    return;
                                input_empty = strlen(localpassword) == 0 ? 1 : 0;
                                pwd_same = strcmp(passwordhash, user.password) == 0 ? 1 : 0;
                                sha256(localpassword, passwordhash);
                            } while (input_empty || pwd_same);

                            do
                            {
                                char message[100];
                                if (input_empty)
                                {
                                    strcpy(message, "The password must not be empty: ");
                                }
                                else
                                {
                                    strcpy(message, "Re-enter the new password: ");
                                }
                                if (getPassword(message, confpassword, MAX_PASSWORD) == -1)
                                    return;
                                input_empty = strlen(confpassword) == 0 ? 1 : 0;
                            } while (input_empty);

                            sha256(localpassword, passwordhash);
                            if (!checkPassword(confpassword, passwordhash))
                            {
                                printf("The passwords are not identical!\n");
                                printf("Press any key to continue...");
                                return;
                            }
                        }
                        else
                        {
                            showPasswordGenerator(localpassword, MAX_PASSWORD);
                            sha256(localpassword, passwordhash);
                        }
                        if (strlen(localpassword) != 0)
                        {
                            strcpy(user.password, passwordhash);
                            user.reset_password = 0;
                            saveUser(user);
                            printf("The password was successfully saved.\n");
                            printf("Press any key to continue...");
                            getch();
                        }
                        else
                        {
                            printf("An error has occurred.\n");
                            printf("Press any key to continue...");
                            fflush(stdin);
                            getch();
                        }
                    }
                    else
                    {
                        //-------------------------Confirmation Message----------------------//
                        logged_in = 1;
                        printf("You have been logged in successfully.\n");
                        printf("Press any key to continue...\n");
                        getch();
                        //-------------------------Confirmation Message----------------------//
                        struct UserData user;
                        int index = getUserByName(localusername, &user);
                        if (user.login_warning)
                        {
                            clearScreen();
                            printf("In the past someone tried to log in to your account!\n");
                            printf("To ensure the security of your account use a strong password with at least 10 characters and consisting of uppercase and lowercase letters and special characters!\n");
                            printf("Press any key to continue...");
                            getch();
                            user.login_warning = 0;
                        }
                        saveUser(user); // Der geaenderte Benutzer wird abgespeichert
                    }
                }
                // Wenn der Benutzer alle 3 Versuche sich anzumelden verbraucht hat:
                if (pwd_trys == 0)
                {
                    struct UserData user;
                    int index = getUserByName(localusername, &user); // Der Benutzer wird anhand des Benutzernamens ermittelt und in die Variable vom Typ USERDATA geschrieben
                    user.login_warning = 1;                          // Die Variable die angiebt ob ein Benutzer sich nicht anmelden konnte wird auf True gesetzt.
                    saveUser(user);                                  // Der geaenderte Benutzer wird abgespeichert
                    // Es werden 5 Sekunden gewartet, bis der Benutzer das Passwort wieder eingeben darf.
                    for (int i = config.retry_passwort_timeout; i > 0; i--)
                    {
                        sleep(1);
                        printf("Wait for %d seconds...\r", i);
                    }
                    // Der Stream STDIN wird geloescht
                    fflush(stdin);
                    pwd_trys = config.password_trys; // Die Variable fuer die Versuche wird wieder auf 3 gesetzt.
                }
            }
        } while (error < 0);
    }
    else
    {
        printf("There are no users");
        printf("Press any key to continue...");
        getch();
    }
}

void showNewUserScreen(char *localusername, char *email, char *phonenumber, char *localpassword, char *localfirstname, char *locallastname, char *localansprache)
{
    clearScreen();
    char cenzored_password[MAX_PASSWORD];
    for (int i = 0; i < strlen(localpassword); i++)
    {
        strcat(cenzored_password, "*");
    }
    printf("--------------------------------------------------------\n");
    printf(" Username: %-5s Password: %s\n", localusername, cenzored_password);
    printf(" First name: %-5s Last name: %s\n", localfirstname, locallastname);
    printf(" Email: %-5s Phone number: %s\n ", email, phonenumber);
    printf(" Address: %s\n", localansprache);
    printf("--------------------------------------------------------\n");
}

void showNewUserMenu()
{
    clearScreen();

    struct UserData users[MAX_USERS];
    if (getUsers(users) >= MAX_USERS)
    {
        printf("You cannot create more Users than allowed\n");
        printf("Press a key to continue ...\n");
        getch();
    }
    else
    {
        char localusername[MAX_USERNAME];
        char localpassword[MAX_PASSWORD];
        char localemail[MAX_EMAIL];
        char localphonenumber[MAX_PHONENUMBER];
        char localfirstname[MAX_FIRSTNAME];
        char locallastname[MAX_LASTNAME];
        char localansprache[MAX_ANSPRACHE];

        memset(localusername, 0, sizeof(localusername));
        memset(localemail, 0, sizeof(localemail));
        memset(localphonenumber, 0, sizeof(localphonenumber));
        memset(localpassword, 0, sizeof(localpassword));
        memset(localfirstname, 0, sizeof(localfirstname));
        memset(locallastname, 0, sizeof(locallastname));
        memset(localansprache, 0, sizeof(localansprache));

        int user_exists = 0;
        int valid_input = 1;
        int input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (user_exists)
            {
                printf("This username does already exist, please choose another one: ");
            }
            else if (input_empty)
            {
                printf("The Usename is required: ");
            }
            else if (!valid_input)
            {
                printf("The username must not contain a ':' or a ';': ");
            }
            else
            {
                printf("Please enter a Username: ");
            }
            fgets(localusername, MAX_USERNAME, stdin);
            str_trim(localusername);
            if (strlen(localusername) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(localusername);
            user_exists = UserExists(localusername);
        } while (user_exists || !valid_input || input_empty);

        valid_input = 1;
        int valid_format = 1;
        input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (!valid_input)
            {
                printf("The E-Mail must not contain a ':' or a ';': ");
            }
            else if (input_empty)
            {
                printf("A E-Mail is required: ");
            }
            else if (!valid_format)
            {
                printf("The E-Mail is not valid: ");
            }
            else
            {
                printf("Please enter a E#-Mail: ");
            }
            fgets(localemail, MAX_LASTNAME, stdin);
            str_trim(localemail);
            if (strlen(localemail) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(locallastname);
            valid_format = validate_email(localemail);
        } while (!valid_input || input_empty || !valid_format);

        valid_input = 1;
        valid_format = 1;
        input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (!valid_input)
            {
                printf("The Phonenumber must not contain a ':' or a ';': ");
            }
            else if (input_empty)
            {
                printf("A Phonenumber is required: ");
            }
            else if (!valid_format)
            {
                printf("The Phonenumber is invalid: ");
            }
            else
            {
                printf("Please enter your Phonenumber: ");
            }
            fgets(localphonenumber, MAX_FIRSTNAME, stdin);
            str_trim(localphonenumber);
            if (strlen(localphonenumber) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(localphonenumber);
            valid_format = validate_phone_number(localphonenumber);
        } while (!valid_input || input_empty || !valid_format);

        valid_input = 1;
        input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (!valid_input)
            {
                printf("The First Name must not contain a ':' or a ';': ");
            }
            else if (input_empty)
            {
                printf("A First Name is required: ");
            }
            else
            {
                printf("Please enter your First Name: ");
            }
            fgets(localfirstname, MAX_FIRSTNAME, stdin);
            str_trim(localfirstname);
            if (strlen(localfirstname) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(localfirstname);
        } while (!valid_input || input_empty);

        valid_input = 1;
        input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (!valid_input)
            {
                printf("The Last Name must not contain a ':' or a ';': ");
            }
            else if (input_empty)
            {
                printf("A Last Name is required: ");
            }
            else
            {
                printf("Please enter your Last Name: ");
            }
            fgets(locallastname, MAX_LASTNAME, stdin);
            str_trim(locallastname);
            if (strlen(locallastname) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(locallastname);
        } while (!valid_input || input_empty);

        valid_input = 1;
        input_empty = 0;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            if (!valid_input)
            {
                printf("The Salutation must not contain a ':' or a ';': ");
            }
            else if (input_empty)
            {
                printf("A Salutaion is required: ");
            }
            else
            {
                printf("Please enter a Salutation (Mr, Mrs, Mx): ");
            }
            fgets(localansprache, MAX_ANSPRACHE, stdin);
            str_trim(localansprache);
            if (strlen(localansprache) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            valid_input = validate_format(localansprache);
        } while (!valid_input || input_empty);

        char buffer[MAX_PASSWORD];
        char pmin;
        do
        {
            showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            printf("Do you want to use a Password Generator?[Y/N]: ");
            pmin = getchar();
        } while (pmin != 'N' && pmin != 'Y');

        if (pmin == 'Y')
        {
            showPasswordGenerator(localpassword, MAX_PASSWORD);
        }
        else
        {
            char conf;
            input_empty = 0;
            do
            {
                clearScreen();
                showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
                fflush(stdin);
                int pwderror = getPassword("Please enter a Password: ", localpassword, MAX_PASSWORD);
                if (strlen(localpassword) > 0)
                {
                    input_empty = 0;
                }
                else
                {
                    input_empty = 1;
                }
                if (pwderror >= 0 && !input_empty)
                {
                    str_trim(localpassword);

                    if (password_common(localpassword))
                    {
                        do
                        {
                            printf("Do you want to use a frequent Password[Y/N]: ");
                            conf = getchar();
                        } while (conf != 'Y' && conf != 'N');
                    }
                    else if (checkPasswordStrength(localpassword) < 20)
                    {
                        do
                        {
                            printf("This Password is very weak, do you want to use it anyway?[Y/N]: ");
                            conf = getchar();
                        } while (conf != 'Y' && conf != 'N');
                    }
                    else
                    {
                        conf = 'Y';
                    }
                }
                else
                {
                    return;
                }
            } while (conf != 'Y' || input_empty);

            fflush(stdin);
            int pwderror = getPassword("Please enter the password again", buffer, MAX_PASSWORD);

            if (pwderror >= 0)
            {
                str_trim(buffer);

                if (strcmp(localpassword, buffer) != 0)
                {
                    printf("The Passwords are not equal!\n");
                    printf("Press any key to return to the Main Menu...\n");
                    getch();
                    return;
                }
            }
            else
            {
                return;
            }
        }

        showNewUserScreen(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
        printf("Is this Information correct?[Y/N]: ");
        fflush(stdin);
        if (getchar() == 'Y')
        {
            printf("Creating User ...\n");
            createUser(localusername, localemail, localphonenumber, localpassword, localfirstname, locallastname, localansprache);
            printf("The User was created successfully!\n");
            fflush(stdin);
            getchar();
        }
    }
}

void showOptions()
{
    while (1)
    {
        clearScreen();
        struct ConfigData config;
        getConfig(&config);
        printf("[0] Return to the Main Menu\n");
        printf("[1] Change the waiting time between re-entering the password(%d)\n", config.retry_passwort_timeout);
        printf("[2] Change the number of password attempts(%d)\n", config.password_trys);
        printf("[3] Deadline for the one password(%s)\n", config.password_deadline);
        printf("[z] Reset settings\n");
        fflush(stdin);

        printf("\n\n# ");
        char opt = getch();
        if (opt == '0')
        {
            return;
        }
        if (opt == '1')
        {
            int timeout = 0;
            printf("\nEnter the new time in seconds: ");
            scanf("%d", &timeout);
            config.retry_passwort_timeout = timeout;
        }
        if (opt == '2')
        {
            int trys = 0;
            printf("\nEnter the new number of password attempts: ");
            scanf("%d", &trys);
            config.password_trys = trys;
        }
        if (opt == '2')
        {
            printf("\nEnter the new deadline: ");
            getDate(config.password_deadline);
        }
        if (opt == 'z')
        {
            resetConfig();
        }
        setConfig(config);
    }
}

void showUserOptions()
{
    while (1)
    {
        clearScreen();
        if (logged_in)
        {
            printf("Good day %s %s %s\n\n", current_user.salutation, current_user.firstname, current_user.lastname);
            printf("Username: %s\n", current_user.username);
            printf("E-Mail: %s\n", current_user.email);
            printf("Phonenumber: %s\n", current_user.phonenumber);
            printf("First Name: %s\n", current_user.firstname);
            printf("Last Name: %s\n", current_user.lastname);
            printf("Permission: %s\n", current_user.group.name);
            printf("\n");
            printf("[0] Back to the main menu\n");
            printf("[1] Edit user\n");
            printf("[2] Delete user\n");

            char in = getch();
            switch (in)
            {
            case '0':
                return;
                break;
            case '1':
                showEditUserMenu();
                break;
            case '2':
                deleteUser(current_user.uuid);
                return;
                break;
            }
        }
        else
        {
            printf("You are not logged in!\n");
            printf("Press any key to return to the main menu ...");
            getch();
            return;
        }
    }
}

void showEditUserMenu()
{
    while (1)
    {
        struct UserData user;
        getUserByUUID(current_user.uuid, &user);
        clearScreen();
        printf("Good day %s %s\n\n", user.salutation, user.firstname, user.lastname);
        printf("Username: %s\n", user.username);
        printf("Email: %s\n", current_user.email);
        printf("Phone number: %s\n", current_user.phonenumber);
        printf("First name: %s\n", user.firstname);
        printf("Last name: %s\n", user.lastname);
        printf("%s", current_user.autologin ? "Autologin is enabled!\n" : "Autologin is not enabled!\n");
        printf("\n\n");
        printf("[0] Back to the user options\n");
        printf("[1] %s\n", current_user.autologin ? "Disable autologin" : "Enable autologin");
        printf("[2] Change username");
        printf("[3] change email");
        printf("[4] Change phone number");
        printf("[5] Change first name");
        printf("[6] Last name aendern\n");
        printf("[7] change password");
        int in = getch();

        switch (in)
        {
        case '0':
            return;
            break;
        case '1':
            current_user.autologin = current_user.autologin ? 0 : 1;
            saveUser(current_user);
            break;
        case '2':
            changeUser(current_user.uuid, "username");
            break;
        case '3':
            changeUser(current_user.uuid, "email");
            break;
        case '4':
            changeUser(current_user.uuid, "Rufnummer");
            break;
        case '5':
            changeUser(current_user.uuid, "vorname");
            break;
        case '6':
            changeUser(current_user.uuid, "Nachname");
            break;
        case '7':
            changeUser(current_user.uuid, "Passwort");
            break;
        }
    }
}

void showUserManager()
{
    struct UserData users[MAX_USERS];
    while (1)
    {
        clearScreen();
        int amount = getUsers(users);
        for (int i = 0; i < amount; i++)
        {
            struct UserData user = users[i];
            struct GroupData group;
            printf("[ID: %d] UUID: %s | username: %s | firstname: %s | lastname: %s | salutation: %s | permission: %s\n", i, user.uuid, user.username, user.firstname, user.lastname, user.salutation, user.group.name);
        }

        int id = -1;
        do
        {
            if (id >= 0 && id < amount)
            {
                break;
            }
            else if (id >= amount && id < -1)
            {
                printf("Dieser Benutzer exestiert nicht!");
            }
            printf("\nID: ");
            scanf(" %d", &id);
        } while (1);

        while (1)
        {
            amount = getUsers(users);
            clearScreen();
            printf("UUID: %s\n", users[id].uuid);
            printf("Benutzername: %s\n", users[id].username);
            printf("Email: %s\n", users[id].email);
            printf("Telefonnummer: %s\n", users[id].phonenumber);
            printf("Vorname: %s\n", users[id].firstname);
            printf("Nachname: %s\n", users[id].lastname);
            printf("Ansprache: %s\n", users[id].salutation);
            printf("Berechtigung: %s\n", users[id].group.name);
            printf("%s\n", users[id].autologin ? "Autologin ist aktiviert!" : "Autologin ist nicht aktiviert!");
            printf("%s", users[id].login_warning ? "Die Warnung für einen unerlaubten Zugriff wurde ausgeloest!\n" : "");
            printf("%s", users[id].reset_password ? "Die Passwortzuruecksetztung wurde fuer diesen Benutzer aktiviert!\n" : "");
            printf("\n");

            printf("\n");
            printf("[0] Zurueck zum Hauptmenue\n");
            printf("[1] Berechtigungen aendern\n");
            printf("%s", !users[id].reset_password ? "[2] Passwort zuruecksetzten\n" : "");
            printf("\n\n");
            printf("# ");
            char opt = getch();
            if (opt == '0')
            {
                return;
            }
            if (opt == '1')
            {
                changeUser(users[id].uuid, "permission");
            }
            if (opt == '2' && strcmp(users[id].password, "null") != 0)
            {
                changeUser(users[id].uuid, "resetPassword");
            }
        }
    }
}

void showGroupManager()
{
    int groups_amount;
    do
    {
        clearScreen();
        struct GroupData groups[MAX_GROUPS];
        groups_amount = getGroups(groups);

        if (groups_amount > 0)
        {
            for (int i = 0; i < groups_amount; i++)
            {
                struct GroupData group = groups[i];
                printf("[%d] %s: %s\n", i, group.name, group.uuid);
            }
        }
        else
        {
            printf("Es exestieren keine Gruppen!\n");
        }
        printf("\n\n");
        printf("[0] Zurueck zum Hauptmenue\n");
        printf("[1] Gruppe erstellen\n");
        if (groups_amount > 0)
            printf("[2] Guppe bearbeiten\n");
        if (groups_amount > 0)
            printf("[3] Guppe loeschen\n");
        printf("\n\n");
        printf("# ");
        char opt = getch();

        switch (opt)
        {
        case '0':
            return;
        case '1':
            if (groups_amount >= MAX_GROUPS)
            {
                printf("Es kann keine weitere Gruppe erstellt werden, da die maximale Anzahl an Gruppen erreicht ist.\n");
            }
            else
            {
                char name[MAX_GROUP_NAME];
                int group_exists = 0;
                do
                {
                    if (group_exists == 1)
                    {
                        printf("Diese Gruppe exestiert bereits: ");
                    }
                    else if (group_exists == -1)
                    {
                        printf("Der Guppenname darf nicht leer sein: ");
                    }
                    else
                    {
                        printf("\nBitte gieb den Namen der Gruppe ein: ");
                    }
                    fgets(name, MAX_GROUP_NAME, stdin);
                    str_trim(name);
                    if (strlen(name) == 0)
                    {
                        group_exists = -1;
                    }
                    else
                    {
                        group_exists = GroupExists(name);
                    }
                } while (group_exists);
                int permissions[MAX_PERMISSIONS];
                for (int i = 0; i < MAX_PERMISSIONS; i++)
                {
                    permissions[i] = 0;
                }
                printf("Gruppe wird erstellt...\n");
                createGroup(name, permissions, 1);
                printf("Die Gruppe '%s' wurde erstellt.\n", name);
                printf("Druecke eine beliebige Taste um fortzufahren...");
                getchar();
            }
            break;
        case '2':
            int id = -1;
            printf("\nBitte gieb die ID ein: ");
            scanf("%d", &id);
            if (GroupExists(groups[id].name))
            {
                showEditGroupMenu(id);
            }
            else
            {
                printf("Diese Gruppe exestiert nicht!\n");
                printf("Druecke eine beliebige Taste um fortzufahren...");
                getch();
            }
            break;
        case '3':
            id = -1;
            printf("\nBitte gieb die ID ein: ");
            scanf(" %d", &id);
            if (GroupExists(groups[id].name))
            {
                deleteGroup(id);
            }
            else
            {
                printf("Diese Gruppe exestiert nicht!\n");
                printf("Druecke eine beliebige Taste um fortzufahren...");
                getch();
            }
            break;
        }
    } while (1);
}

void showEditGroupMenu(int id)
{
    while (1)
    {
        clearScreen();
        struct GroupData groups[MAX_GROUPS];
        memset(groups, 0, sizeof(struct GroupData) * MAX_GROUPS);
        struct GroupData group;
        int index = getGroupByID(id, &group);
        int group_amount = getGroups(groups);
        int haspermission = 0;
        printf("--------------%s--------------\n\n", group.name);
        if (group.permissions[PERMISSION_ALL])
        {
            printf("Alle Berechtigungen\n");
            haspermission = 1;
        }
        if (group.permissions[PERMISSION_MANAGE_USERS] && !group.permissions[PERMISSION_ALL])
        {
            printf("Benutzer verwalten\n");
            haspermission = 1;
        }
        if (group.permissions[PERMISSION_MANAGE_GROUPS] && !group.permissions[PERMISSION_ALL])
        {
            printf("Gruppen verwalten\n");
            haspermission = 1;
        }
        if (group.permissions[PERMISSION_ANALYTICS] && !group.permissions[PERMISSION_ALL])
        {
            printf("Analytics lesen\n");
            haspermission = 1;
        }
        if (!haspermission)
        {
            printf("Diese Gruppe verfuegt ueber keine spezielle Berechtigung!");
        }

        printf("\n\n");
        printf("[0] Zurueck zur Gruppenverwaltung\n");
        printf("[1] Alle Berechtigungen\n");
        printf("[2] Benutzer verwalten\n");
        printf("[3] Gruppen verwalten\n");
        printf("[4] Analysen lesen\n");
        printf("[5] Einstellungen aendern\n");
        printf("\n\n# ");

        fflush(stdin);
        char in = getch();

        if (in == '0')
        {
            return;
        }
        if (in == '1')
        {
            if (group.permissions[PERMISSION_ALL])
            {
                group.permissions[PERMISSION_ALL] = 0;
            }
            else
            {
                group.permissions[PERMISSION_ALL] = 1;
            }
        }
        if (in == '2')
        {
            if (group.permissions[PERMISSION_MANAGE_USERS])
            {
                group.permissions[PERMISSION_MANAGE_USERS] = 0;
            }
            else
            {
                group.permissions[PERMISSION_MANAGE_USERS] = 1;
            }
        }
        if (in == '3')
        {
            if (group.permissions[PERMISSION_MANAGE_GROUPS])
            {
                group.permissions[PERMISSION_MANAGE_GROUPS] = 0;
            }
            else
            {
                group.permissions[PERMISSION_MANAGE_GROUPS] = 1;
            }
        }
        if (in == '4')
        {
            if (group.permissions[PERMISSION_ANALYTICS])
            {
                group.permissions[PERMISSION_ANALYTICS] = 0;
            }
            else
            {
                group.permissions[PERMISSION_ANALYTICS] = 1;
            }
        }
        if (in == '5')
        {
            if (group.permissions[PERMISSION_CONFIGURATION])
            {
                group.permissions[PERMISSION_CONFIGURATION] = 0;
            }
            else
            {
                group.permissions[PERMISSION_CONFIGURATION] = 1;
            }
        }

        groups[id] = group;
        char data[MAX_USER_FILE_SIZE];
        memset(data, 0, sizeof(data));
        for (int i = 0; i < group_amount; i++)
        {
            char str[10];
            memset(str, 0, sizeof(str));
            sprintf(str, "%d", groups[i].id);
            strcat(data, str);
            strcat(data, ";");
            strcat(data, groups[i].uuid);
            strcat(data, ";");
            strcat(data, groups[i].name);
            for (int j = 0; j < MAX_PERMISSIONS; j++)
            {
                strcat(data, ";");
                char lstr[2];
                sprintf(lstr, "%d", groups[i].permissions[j]);
                strcat(data, lstr);
            }
            strcat(data, ":");
        }
        writeFile(data, groups_file);
    }
}

void showTodoList()
{
    char searchstr[MAX_TODO_SEARCH_STRING];
    memset(searchstr, 0, sizeof(searchstr));
    while (1)
    {
        clearScreen();
        struct TodoData todos[MAX_TODOS];
        int todo_amount = getTodosByUserUUID(current_user.uuid, todos);
        int search_amount = 0;
        if (todo_amount > 0)
        {
            for (int i = 0; i < todo_amount; i++)
            {
                if (strlen(searchstr) > 0 && strstr(todos[i].description, searchstr) != NULL)
                {
                    printf("[%d] %s: %s\n", i, todos[i].name, todos[i].description);
                    search_amount++;
                }
                else if (strlen(searchstr) == 0)
                {
                    printf("[%d] %s: %s\n", i, todos[i].name, todos[i].description);
                }
            }
            if (search_amount == 0 && strlen(searchstr) != 0)
            {
                printf("Es wurden keine Suchergebnisse gefunden.\n");
            }
            else if (search_amount > 0 && strlen(searchstr) != 0)
            {
                printf("Es wurden %d Todo Listen gefunden.\n", todo_amount);
            }
        }
        else if (todo_amount == -1)
        {
            printf("Es ist ein Fehler aufgetreten!");
        }
        else
        {
            printf("Es exestieren aktuell keine TODO Listen.\n");
        }
        printf("\n\n");
        printf("[0] Zurueck zum Hauptmenue\n");
        printf("[1] TODO Liste erstellen\n");
        if (todo_amount > 0)
        {
            printf("[2] TODO Liste bearbeiten\n");
            printf("[3] TODO Liste loeschen\n");
            printf("%s", strlen(searchstr) == 0 ? "[4] In der Beschreibung suchen\n" : "[4] Suche entfernen\n");
        }
        char in = -1;
        printf("# ");
        in = getch();
        if (in == '0')
        {
            return;
        }
        if (in == '1')
        {
            showCreateTodo();
        }
        if (in == '2' && todo_amount > 0)
        {
            showEditTodo();
        }
        if (in == '3' && todo_amount > 0)
        {
            showDeleteTodo();
        }
        if (in == '4' && todo_amount > 0)
        {
            if (strlen(searchstr) == 0)
            {
                printf("\nGib den String ein, den du suchen moechtest: ");
                fflush(stdin);
                fgets(searchstr, MAX_TODO_SEARCH_STRING, stdin);
                str_trim(searchstr);
            }
            else
            {
                strcpy(searchstr, "");
            }
        }
    }
}

void showCreateTodo()
{
    struct TodoData todos[MAX_TODOS];
    if (getTodos(todos) >= MAX_TODOS)
    {
        printf("Es kann keine TODO Liste erstellt werden, da die maximale Anzahl an TODO Listen erreicht ist.\n");
        printf("Druecke eine beliebige Taste um fortzufahren.\n");
        getch();
    }
    else
    {
        struct TodoData todo;
        char name[MAX_TODO_NAME];
        char description[MAX_TODO_DESCRIPTION];
        char ldescription[MAX_TODO_DESCRIPTION]; // Wird verwendet, um ein Problem zu umgehen, wo die description leer bleibt
        char deadline[MAX_TODO_DEATHLINE];

        int valid_input = 1;
        int todo_exists = 0;
        do
        {
            if (!valid_input)
            {
                printf("Der Name der TODO Liste, darf keinen ':' und kein ';' enthalten: ");
            }
            else if (todo_exists)
            {
                printf("Eine TODO Liste mit diesem Namen exestiert bereits: ");
            }
            else
            {
                printf("\nGib einen Namen deiner TODO Liste ein: ");
            }
            fflush(stdin);
            fgets(name, MAX_TODO_NAME, stdin);
            str_trim(name);
            valid_input = validate_format(name);
            todo_exists = todoExists(name);
        } while (!valid_input || todo_exists);

        valid_input = 1;
        do
        {
            if (valid_input)
            {
                printf("Gib eine Beschreibung fuer deine TODO Liste ein: ");
            }
            else
            {
                printf("Die Beschreibung der TODO Liste, darf keinen ':' und kein ';' enthalten: ");
            }
            fflush(stdin);
            fgets(ldescription, MAX_TODO_DESCRIPTION, stdin);
            valid_input = validate_format(ldescription);
            str_trim(ldescription);
        } while (!valid_input);

        char conf;
        do
        {
            printf("Moechtest du eine Deadline festlegen?[Y/N]: ");
            fflush(stdin);
            conf = getchar();
        } while (conf != 'Y' && conf != 'N');
        if (conf == 'Y')
        {
            getDate(deadline);
        }
        else
        {
            strcpy(deadline, "null");
        }
        strcpy(description, ldescription);
        createTodo(name, description, deadline);
    }
}

void showEditTodo()
{
    int id = 0;
    int todoexists = 0;
    do
    {
        if (todoexists != -1)
        {
            printf("\nBitte gieb die ID des Todos ein: ");
        }
        else
        {
            printf("Dieses Todo exestiert nicht, gib eine andere ID ein: ");
        }
        scanf("%d", &id);
        struct TodoData todo;
        todoexists = getTodoByID(id, &todo);
    } while (todoexists == -1);

    while (1)
    {
        clearScreen();
        struct TodoData todo;
        int index = getTodoByID(id, &todo);
        printf("-----------------------%s-----------------------\n", todo.name);
        int j = 0;
        for (int i = 0; i < todo.entry_count; i++)
        {
            if (strcmp(todo.entries[i], "null") != 0)
            {
                printf("[%d] %s\n", j, todo.entries[i]);
                j++;
            }
        }
        if (j == 0)
        {
            printf("Es exestieren aktuell keine Eintraege!\n");
        }
        printf("\n");
        printf("--------------Menu------------\n");
        printf("[0] Zurueck zu den TODO Listen\n");
        printf("[1] Name der TODO Liste aendern\n");
        printf("[2] Eintrag hinzufuegen\n");
        if (j > 0)
        {
            printf("[3] Eintrag bearbeiten\n");
            printf("[4] Eintrag loeschen\n");
        }
        char in = getch();

        if (in == '0')
        {
            return;
        }
        if (in == '1')
        {
            changeTodo(todo.uuid, "name");
        }
        if (in == '2')
        {
            changeTodo(todo.uuid, "addEntry");
        }
        if (j > 0 && in == '3')
        {
            changeTodo(todo.uuid, "editEntry");
        }
        if (j > 0 && in == '4')
        {
            changeTodo(todo.uuid, "removeEntry");
        }
    }
}

void showDeleteTodo()
{
    int id = 0;
    struct TodoData todo;
    printf("Gib die ID der TODO Liste ein: ");
    scanf(" %d", &id);
    int index = getTodoByID(id, &todo);
    if (index >= 0)
    {
        char conf;
        do
        {
            printf("Moechtest du die TODO Liste '%s' wirklich loeschen?[Y/N]: ", todo.name);
            fflush(stdin);
            conf = getchar();
            if (conf == 'Y')
            {
                deleteTodo(todo.uuid);
                addAnalytic(ANALYTICS_DELETE_USER);
            }
        } while (conf != 'Y' && conf != 'N');
    }
    else
    {
        printf("Diese TODO Liste exestiert nicht!\n");
        printf("Druecke eine belibige Taste um fortzufahren...");
        getch();
    }
}

void showPasswordManager()
{
    clearScreen();
    struct PasswordEntry pes[MAX_PM_PES];
    struct ConfigData config;
    getConfig(&config);
    char message[MAX_PM_PE_PASSWORD];
    char hash[MAX_HASH];
    char password[MAX_PASSWORD];
    int validpassword = 1;
    int pwd_trys = config.password_trys;

    //------------------Passwort ueberpruefen---------------------
    do
    {
        if (validpassword == 1)
        {
            strcpy(message, "Bitte gib dein Passwort ein");
        }
        else if (validpassword == 0)
        {
            if (pwd_trys == 0)
            {
                for (int i = config.retry_passwort_timeout; i > 0; i--)
                {
                    sleep(1);
                    printf("Du wirst in %d Sekunden abgemeldet!\r", i);
                }
                Logout();
                return;
            }
            else
            {
                pwd_trys--;
                char str[2];
                sprintf(str, "%d", pwd_trys);
                strcpy(message, "Das Passwort ist falsch, du hast noch ");
                strcat(message, str);
                strcat(message, " versuche");
            }
        }
        int error = getPassword(message, password, MAX_PASSWORD);
        if (error == -1)
        {
            return;
        }
        sha256(password, hash);
        if (strcmp(hash, current_user.password) != 0)
        {
            validpassword = 0;
        }
    } while (validpassword == 0);
    //------------------Passwort ueberpruefen---------------------

    //------------------Menue--------------------
    while (1)
    {
        clearScreen();
        int pe_amount = getPasswordEntries(pes);
        if (pe_amount > 0)
        {
            for (int i = 0; i < pe_amount; i++)
            {
                printf("[%d] %s\n", i, pes[i].name);
            }
        }
        else
        {
            printf("Es exestieren aktuell kein Eintraege.");
        }
        printf("\n\n");
        printf("[0] Zurueck zum Hauptmenue\n");
        printf("[1] Eintrag hinzufuegen\n");
        if (pe_amount > 0)
        {
            printf("[2] Eintrag bearbeiten\n");
            printf("[3] Eintrag loeschen\n");
        }
        char in = getch();

        if (in == '0')
        {
            return;
        }
        else if (in == '1')
        {
            addPasswordEntry();
        }
        else if (in == '2' && pe_amount > 0)
        {
            editPasswordEntry();
        }
        else if (in == '3' && pe_amount > 0)
        {
            deletePasswordEntry();
        }
    }
    //------------------Menue--------------------
}

void showPasswordGenerator(char *password, int length)
{
    int capitalletters = 1;
    int noncapitalletters = 1;
    int specialletters = 0;

    int amount = 10;
    while (1)
    {
        clearScreen();

        printf("------------------Password Generator------------------\n");
        printf("                       Pattern:\n");
        printf(capitalletters == 1 ? "                   Grossbuchstaben\n" : "");
        printf(noncapitalletters == 1 ? "                   Kleinbuchstaben\n" : "");
        printf(specialletters == 1 ? "                   Sonderzeichen\n" : "");
        printf("                Anzahl der Zeichen: %d\n", amount);
        printf("------------------------------------------------------\n");

        printf("[0] Passwort generieren\n");
        printf("[1] Grossbuchstaben umschalten\n");
        printf("[2] Kleinbuchstaben umschalten\n");
        printf("[3] Sonderzeichen umschalten\n");
        printf("[4] Passwortgroesse festlegen\n");
        char in = getch();

        switch (in)
        {
        case '0':
            clearScreen();
            generatePassword(capitalletters, noncapitalletters, specialletters, amount, password);
            printf("Dein Passwort ist: %s\n", password);
            char conf;
            do
            {
                printf("Moechtest du dieses anwenden?[Y/N]: ");
                fflush(stdin);
                conf = getchar();
                if (conf == 'Y')
                {
                    return;
                }
            } while (conf != 'Y' && conf != 'N');
            break;
        case '1':
            if (capitalletters == 0)
            {
                capitalletters = 1;
            }
            else
            {
                capitalletters = 0;
            }
            break;
        case '2':
            if (noncapitalletters == 0)
            {
                noncapitalletters = 1;
            }
            else
            {
                noncapitalletters = 0;
            }
            break;
        case '3':
            if (specialletters == 0)
            {
                specialletters = 1;
            }
            else
            {
                specialletters = 0;
            }
            break;
        case '4':
            clearScreen();
            int validinput = 1;
            do
            {
                if (validinput)
                {
                    printf("Bitte gieb eine neue Groesse ein: ");
                }
                else
                {
                    printf("Die Laenge des Passwortes darf '%d' nicht ueberschreiten: ", length);
                }
                scanf(" %d", &amount);
                validinput = amount <= length ? 1 : 0;
            } while (!validinput);
            break;
        }
    }
}

void generatePassword(int capitalletters, int noncapitalletters, int specialletters, int amount, char *password)
{

    char capital_letters[26] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    char non_capital_letters[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    char special_characters[11] = {'!', '@', '#', '$', '^', '&', '*', '(', ')', '-', '_'};

    char buffer[amount + 1];

    int max;
    int option_max;
    // printf("Amount: %d\n", amount);
    for (int i = 0; i < amount; i++)
    {
        int rand_option = random(1, 3);
        // printf("rand_option: %d\n", rand_option);
        switch (rand_option)
        {
        case 1:
            if (capitalletters)
                max = 26;
            break;
        case 2:
            if (noncapitalletters)
                max = 26;
            break;
        case 3:
            if (specialletters)
                max = 11;
            break;
        }

        int rand = random(1, max);
        // printf("rand: %d\n", rand);
        if (rand <= 26 && rand_option == 1 && capitalletters)
        {
            // printf("letter: %c\n", capital_letters[rand-1]);
            buffer[i] = capital_letters[rand - 1];
        }
        else if (rand <= 26 && rand_option == 2 && noncapitalletters)
        {
            // printf("letter: %c\n", non_capital_letters[rand-1]);
            buffer[i] = non_capital_letters[rand - 1];
        }
        else if (rand <= 11 && rand_option == 3 && specialletters)
        {
            // printf("letter: %c\n", special_characters[rand-1]);
            buffer[i] = special_characters[rand - 1];
        }
        else
        {
            i--;
        }
    }
    buffer[amount] = '\0';
    strcpy(password, buffer);
}

int Login(char *localusername, char *localpassword)
{
    str_trim(localusername);
    str_trim(localpassword);

    struct UserData user;
    if (getUserByName(localusername, &user) >= 0)
    {
        if (checkPassword(localpassword, user.password))
        {
            current_user = user;
            if (user.autologin)
            {
                struct ConfigData config;
                getConfig(&config);
                strcpy(config.autologin, user.uuid);
                setConfig(config);
            }
            addAnalytic(ANALYTICS_LOGINS);
            return 0;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return -2;
    }
    return 1;
}

int AutoLogin()
{
    struct UserData user;
    struct ConfigData config;
    getConfig(&config);

    if (getUserByUUID(config.autologin, &user) >= 0)
    {
        if (user.autologin && strcmp(config.autologin, "null") != 0)
        {
            current_user = user;
            logged_in = 1;
            addAnalytic(ANALYTICS_LOGINS);
            return 0;
        }
        return 1;
    }
    else
    {
        strcpy(config.autologin, "null");
        setConfig(config);
        return -2;
    }
}

int Logout()
{
    logged_in = 0;
    struct ConfigData config;
    getConfig(&config);
    strcpy(config.autologin, "null");
    setConfig(config);
}

int checkPassword(char *localpwd, char *localpwdhash)
{
    str_trim(localpwd);
    str_trim(localpwdhash);

    char hash[SHA256_SIZE];
    sha256(localpwd, hash);
    localpwdhash[strlen(hash)] = '\0'; // Damit anderer Text der sich reingeschlichen hat herausgenommen wird.
    if (strcmp(hash, localpwdhash) == 0)
    {
        return 1;
    }
    return 0;
}

void createUser(char *localusername, char *localemail, char *localphonenumber, char *localpassword, char *localfirstname, char *locallastname, char *localansprache)
{
    clearScreen();
    str_trim(localpassword);

    // printf("Benutzer wird erstellt...\n");
    // printf("Passwort wird in einen Hash umgewandelt...");

    char str[MAX_USER_FILE_SIZE];
    char hash[SHA256_SIZE];
    sha256(localpassword, hash);

    char uuid[37];
    generate_uuid(uuid);
    strcpy(str, uuid);
    strcat(str, ";");
    strcat(str, localusername);
    strcat(str, ";");
    strcat(str, localemail);
    strcat(str, ";");
    strcat(str, localphonenumber);
    strcat(str, ";");
    strcat(str, hash);
    strcat(str, ";");
    strcat(str, localfirstname);
    strcat(str, ";");
    strcat(str, locallastname);
    strcat(str, ";");
    strcat(str, localansprache);
    strcat(str, ";");
    struct UserData users[MAX_USERS];
    int amount = getUsers(users);
    if (amount > 0)
    {
        strcat(str, "1"); // Member Gruppe
    }
    else
    {
        strcat(str, "0"); // Admin Gruppe
    }
    strcat(str, ";");
    strcat(str, "1");
    strcat(str, ";");
    strcat(str, "0");
    strcat(str, ";");
    strcat(str, "0");
    strcat(str, ":");

    char path[200];
    strcpy(path, password_manager_folder);
    strcat(path, uuid);
    strcat(path, ".txt");
    if (!fexists(path))
    {
        fcreate(path);
    }

    appendFile(str, users_file);
}

int deleteUser(char *uuid)
{
    printf("Wenn du diesen Benutzer loeschst, werden alle Daten des Benutzers verlohren gehen. Diese Aktion kann nicht mehr rueckgaengig gemacht werden.\n");
    printf("Moechtest du den Benutzer wirkluch loeschen?[Y/N]: ");
    char conf = getchar();
    if (conf == 'Y')
    {
        struct UserData users[MAX_USERS];
        int index = -1;
        char data[MAX_USER_FILE_SIZE];
        int user_amount = getUsers(users);

        for (int i = 0; i < user_amount; i++)
        {
            if (strcmp(users[i].uuid, uuid) == 0)
            {
                index = i;
                break;
            }
        }

        // Alle Passworteintraege loeschen
        char path[200];
        strcpy(path, password_manager_folder);
        strcat(path, users[index].uuid);
        strcat(path, ".txt");
        fdelete(path);

        // Allte TODO Listen loeschen
        struct TodoData todos[MAX_TODOS];
        int todo_amount = getTodos(todos);
        for (int i = 0; i < todo_amount; i++)
        {
            if (strcmp(todos[i].user.uuid, current_user.uuid) == 0)
            {
                deleteTodo(todos[i].uuid);
            }
        }

        int is_other_admin = 0;
        for (int i = 0; i < user_amount; i++)
        {
            if (index != i && users[i].group.id == 0)
            {
                is_other_admin = 1;
                break;
            }
        }

        if (is_other_admin && index >= 0)
        {
            for (int i = 0; i < user_amount; i++)
            {
                if (i != index)
                {
                    strcat(data, users[i].uuid);
                    strcat(data, ";");
                    strcat(data, users[i].username);
                    strcat(data, ";");
                    strcat(data, users[i].email);
                    strcat(data, ";");
                    strcat(data, users[i].phonenumber);
                    strcat(data, ";");
                    strcat(data, users[i].password);
                    strcat(data, ";");
                    strcat(data, users[i].firstname);
                    strcat(data, ";");
                    strcat(data, users[i].lastname);
                    strcat(data, ";");
                    strcat(data, users[i].salutation);
                    strcat(data, ";");
                    char str[10];
                    sprintf(str, "%d", users[i].group.id);
                    strcat(data, str);
                    sprintf(str, "%d", users[i].autologin);
                    strcat(data, str);
                    sprintf(str, "%d", users[i].login_warning);
                    strcat(data, str);
                    sprintf(str, "%d", users[i].reset_password);
                    strcat(data, str);
                    strcat(data, ":");
                }
            }
            writeFile(data, users_file);
            addAnalytic(ANALYTICS_DELETE_USER);
            Logout();
        }
        else
        {
            clearScreen();
            printf("Es muss mindestens ein Benutzer ein Administrator sein.\nBitte aendere die Berechtigung eines anderen Benutzers zu Administrator um diesen Account loeschen zu koennen.\n");
            printf("Druecke eine belibige Taste um zum Hauptmenue zurueck zu kehren...");
            getch();
        }
    }
}

int changeUser(char *uuid, char *mode)
{
    struct UserData user;
    struct UserData users[MAX_USERS];
    int user_amount = getUsers(users);
    int index = getUserByUUID(uuid, &user);
    char perm;
    if (strcmp(mode, "permission") == 0)
    {
        int is_one_admin = 1;
        while (1)
        {
            struct GroupData groups[MAX_GROUPS];
            int group_amount = getGroups(groups);
            clearScreen();
            printf("Bitte waehle eine der folgenden Berechtigungen aus:\n");
            for (int i = 0; i < group_amount; i++)
            {
                printf("[%d] %s\n", i, groups[i].name);
            }
            printf("\n\n");
            if (is_one_admin)
            {
                printf("Bitte waehle eine Option aus: ");
            }
            else
            {
                printf("Es muss mindestens ein Benutzer Administrator sein, bitte waehle eine andere Option aus: ");
            }
            int id = -1;
            scanf(" %d", &id);
            if (id != 0)
            {
                for (int i = 0; i < user_amount; i++)
                {
                    if (users[i].group.id == 0 && i != index)
                    {
                        is_one_admin = 1;
                        break;
                    }
                    else
                    {
                        is_one_admin = 0;
                    }
                }

                if (is_one_admin)
                {
                    struct GroupData group;
                    getGroupByID(id, &group);
                    user.group = group;
                    saveUser(user);
                    printf("Die Gruppe wurde erfolgreich geaendert.\n");
                    printf("Druecke beliebige Taste um fortzufahren...");
                    return 1;
                }
            }
        }
    }
    else if (strcmp(mode, "username") == 0)
    {
        char username[MAX_USERNAME];
        printf("Bitte gieb den neuen Benutzernamen ein: ");
        fflush(stdin);
        fgets(username, MAX_USERNAME, stdin);
        str_trim(username);
        char username1[MAX_USERNAME];
        strcpy(user.username, username);
    }
    else if (strcmp(mode, "firstname") == 0)
    {
        char firstname[MAX_FIRSTNAME];
        printf("Bitte gieb den neuen Vornamen ein: ");
        fgets(firstname, MAX_FIRSTNAME, stdin);
        str_trim(firstname);
        strcpy(user.firstname, firstname);
    }
    else if (strcmp(mode, "lastname") == 0)
    {
        char lastname[MAX_LASTNAME];
        printf("Bitte gieb den neuen Nachnamen ein: ");
        fgets(lastname, MAX_LASTNAME, stdin);
        str_trim(lastname);
        strcpy(user.lastname, lastname);
    }
    else if (strcmp(mode, "email") == 0)
    {
        char email[MAX_LASTNAME];
        printf("Bitte gieb die neue Email ein: ");
        fgets(email, MAX_LASTNAME, stdin);
        str_trim(email);
        strcpy(user.email, email);
    }
    else if (strcmp(mode, "phonenumber") == 0)
    {
        char phonenumber[MAX_LASTNAME];
        printf("Bitte gieb die neue Telefonnummer ein: ");
        fgets(phonenumber, MAX_LASTNAME, stdin);
        str_trim(phonenumber);
        strcpy(user.phonenumber, phonenumber);
    }
    else if (strcmp(mode, "password") == 0)
    {
        int rightPWD = 0;
        int pwd_trys = 3;
        do
        {
            char currpassword[MAX_PASSWORD];
            char newpassword[MAX_PASSWORD];
            char confnewpassword[MAX_PASSWORD];
            if (pwd_trys < 3)
            {
                printf("Das Passwort ist falsch, du hast noch %d Versuche: ", pwd_trys);
            }
            else
            {
                printf("Bitte gieb das Passwort ein: ");
            }

            fgets(currpassword, MAX_PASSWORD, stdin);
            str_trim(currpassword);

            if (checkPassword(currpassword, current_user.password))
            {
                rightPWD = 1;
                getPassword("Bitte gieb dein neues Passwort ein", newpassword, MAX_PASSWORD);
                str_trim(newpassword);

                char conf;
                if (password_common(newpassword))
                {
                    do
                    {
                        printf("Moechtest du wirklich ein haeufiges Passwort verwenden[Y/N]: ");
                        fflush(stdin);
                        conf = getchar();
                    } while (conf != 'Y' && conf != 'N');
                }
                else if (checkPasswordStrength(newpassword) > 40)
                {
                    do
                    {
                        printf("\nDieses Passwort ist sehr schwach, moechtest du es trotzdem verwenden?[Y/N]: ");
                        fflush(stdin);
                        conf = getchar();
                    } while (conf != 'Y' && conf != 'N');
                }
                else
                {
                    conf = 'Y';
                }

                if (conf == 'Y')
                {
                    fflush(stdin);
                    getPassword("Bitte gieb dein neues Passwort erneut ein", confnewpassword, MAX_PASSWORD);
                    str_trim(confnewpassword);

                    if (strcmp(newpassword, confnewpassword) == 0)
                    {

                        char data[MAX_PM_FILE_SIZE];
                        char rawdata[MAX_PM_FILE_SIZE];
                        char path[200];

                        strcpy(path, password_manager_folder);
                        strcat(path, user.uuid);
                        strcat(path, ".txt");
                        readFile(data, path, MAX_PM_FILE_SIZE);

                        zn_decrypt(data, user.password, rawdata);

                        char hash[SHA256_SIZE];
                        sha256(newpassword, hash);
                        strcpy(user.password, hash);

                        zn_encrypt(rawdata, user.password, data);
                        writeFile(data, path);

                        printf("Das Passwort wurde erfolgreich geaendert.\n");
                        printf("Druecke eine belibige Taste um fortzufahren...");
                        getch();
                    }
                }
            }
            else
            {
                rightPWD = 0;
                pwd_trys--;
            }
            if (pwd_trys == 0)
            {
                for (int i = 5; i > 0; i--)
                {
                    sleep(1);
                    printf("Warte noch %d Sekunden...\r", i);
                }
                fflush(stdin);
                pwd_trys = 3;
            }
        } while (!rightPWD);
    }
    else if (strcmp(mode, "resetPassword") == 0)
    {
        struct ConfigData config;
        getConfig(&config);
        strcpy(config.autologin, "null");
        user.reset_password = 1;
        setConfig(config);
    }
    saveUser(user);
}

int getUsers(struct UserData *users)
{
    char data[MAX_USER_FILE_SIZE];
    memset(data, 0, sizeof(data));
    readFile(data, users_file, MAX_USER_FILE_SIZE);
    char *usersstr[MAX_USERS];

    if (strstr(data, ":") != NULL)
    {
        int size = str_split(data, ":", usersstr);
        for (int i = 0; i < size; i++)
        {
            struct UserData userdata;
            char *userdatastr[20];
            str_split(usersstr[i], ";", userdatastr);

            strcpy(userdata.uuid, userdatastr[0]);
            strcpy(userdata.username, userdatastr[1]);
            strcpy(userdata.email, userdatastr[2]);
            strcpy(userdata.phonenumber, userdatastr[3]);
            strcpy(userdata.password, userdatastr[4]);
            strcpy(userdata.firstname, userdatastr[5]);
            strcpy(userdata.lastname, userdatastr[6]);
            strcpy(userdata.salutation, userdatastr[7]);
            struct GroupData group;
            if (getGroupByID(atoi(userdatastr[8]), &group) == -1)
            {
                getGroupByID(1, &group);
            }
            userdata.group = group;
            userdata.autologin = atoi(userdatastr[9]);
            userdata.login_warning = atoi(userdatastr[10]);
            userdata.reset_password = atoi(userdatastr[11]);
            users[i] = userdata;
        }
        return size;
    }
    else
    {
        return 0;
    }
}

int getUserByUUID(char *uuid, struct UserData *user)
{
    struct UserData users[MAX_USERS];
    int users_count = getUsers(users);
    str_trim(uuid);

    for (int i = 0; i < users_count; i++)
    {
        if (strcmp(users[i].uuid, uuid) == 0)
        {
            *user = users[i];
            return i;
        }
    }
    return -1;
}

int getUserByName(char *username, struct UserData *user)
{
    struct UserData users[MAX_USERS];
    int users_count = getUsers(users);
    str_trim(username);

    for (int i = 0; i < users_count; i++)
    {
        if (strcmp(users[i].username, username) == 0)
        {
            *user = users[i];
            return i;
        }
    }
    return 0;
}

void saveUser(struct UserData user)
{
    struct UserData users[MAX_USERS];
    int user_amount = getUsers(users);
    int index = 0;
    for (int i = 0; i < user_amount; i++)
    {
        if (strcmp(user.uuid, users[i].uuid) == 0)
        {
            index = i;
        }
    }
    users[index] = user;
    char data[MAX_USER_FILE_SIZE];
    memset(data, 0, sizeof(data));
    for (int i = 0; i < user_amount; i++)
    {
        strcat(data, users[i].uuid);
        strcat(data, ";");
        strcat(data, users[i].username);
        strcat(data, ";");
        strcat(data, users[i].email);
        strcat(data, ";");
        strcat(data, users[i].phonenumber);
        strcat(data, ";");
        strcat(data, users[i].password);
        strcat(data, ";");
        strcat(data, users[i].firstname);
        strcat(data, ";");
        strcat(data, users[i].lastname);
        strcat(data, ";");
        strcat(data, users[i].salutation);
        strcat(data, ";");
        char str[10];
        sprintf(str, "%d", users[i].group.id);
        strcat(data, str);
        strcat(data, ";");
        char str1[10];
        sprintf(str1, "%d", users[i].autologin);
        strcat(data, str1);
        char str2[10];
        strcat(data, ";");
        sprintf(str2, "%d", users[i].login_warning);
        strcat(data, str2);
        strcat(data, ";");
        char str3[10];
        sprintf(str3, "%d", users[i].reset_password);
        strcat(data, str3);
        strcat(data, ":");
    }
    if (strlen(data) != 0)
    {
        writeFile(data, users_file);
    }
}

int UserExists(char *username)
{
    struct UserData users[MAX_USERS];
    int users_count = getUsers(users);
    str_trim(username);

    for (int i = 0; i < users_count; i++)
    {
        if (strcmp(users[i].username, username) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void createGroup(char *name, int *permissions, int logging)
{
    clearScreen();

    char str[MAX_GROUP_FILE_SIZE];
    struct GroupData groups[MAX_GROUPS];
    int groups_amount = getGroups(groups);
    sprintf(str, "%d", groups_amount);
    strcat(str, ";");
    // printf("UUID wird generiert...");
    char uuid[37];
    generate_uuid(uuid);
    // printf(" -> Done\n");
    // printf("UUID wird hinzugefuegt...");
    strcat(str, uuid);
    // printf(" -> Done\n");
    // printf("Name wird hinzugefuegt...");
    strcat(str, ";");
    strcat(str, name);
    // printf("-> Done\n");
    // printf("Berechtigungen werden inizialisiert...");
    for (int i = 0; i < MAX_PERMISSIONS; i++)
    {
        strcat(str, ";");
        char lstr[2];
        sprintf(lstr, "%d", permissions[i]);
        strcat(str, lstr);
    }
    // printf("-> Done\n");
    strcat(str, ":");
    // printf("Schreiben der Daten in die 'groups.txt' Datei\n");
    appendFile(str, groups_file);
    addAnalytic(ANALYTICS_CREATE_GROUP);
}

void deleteGroup(int id)
{
    printf("Moechtest du die Gruppe wirkluch loeschen?[Y/N]");
    fflush(stdin);
    char conf = getchar();
    if (conf == 'Y')
    {
        struct GroupData groups[MAX_GROUPS];
        char data[MAX_GROUP_FILE_SIZE];

        int group_amount = getGroups(groups);
        for (int i = 0; i < group_amount; i++)
        {
            if (i != id)
            {
                strcat(data, groups[i].uuid);
                strcat(data, ";");
                strcat(data, groups[i].name);
                strcat(data, ";");
                for (int j = 0; j < MAX_PERMISSIONS; j++)
                {
                    char str[10];
                    sprintf(str, "%d", groups[i].permissions[j]);
                    strcat(data, ";");
                    strcat(data, str);
                }
                strcat(data, ":");
            }
        }
        writeFile(data, groups_file);
    }
    addAnalytic(ANALYTICS_DELETE_GROUP);
}

int getGroups(struct GroupData *groups)
{
    char data[MAX_GROUP_FILE_SIZE];
    readFile(data, groups_file, MAX_GROUP_FILE_SIZE);
    char *groupsstr[MAX_GROUPS];

    if (strstr(data, ":") != NULL)
    {
        int size = str_split(data, ":", groupsstr);

        for (int i = 0; i < size; i++)
        {
            struct GroupData groupdata;
            char *groupdatastr[MAX_PERMISSIONS + 3];
            str_split(groupsstr[i], ";", groupdatastr);
            groupdata.id = atoi(groupdatastr[0]);
            strcpy(groupdata.uuid, groupdatastr[1]);
            strcpy(groupdata.name, groupdatastr[2]);
            for (int j = 0; j < MAX_PERMISSIONS; j++)
            {
                groupdata.permissions[j] = atoi(groupdatastr[3 + j]);
            }
            groups[i] = groupdata;
        }
        return size;
    }
    else
    {
        return 0;
    }
}

int GroupExists(char *groupname)
{
    struct GroupData groups[MAX_GROUPS];
    int groups_count = getGroups(groups);
    str_trim(groupname);

    for (int i = 0; i < groups_count; i++)
    {
        if (strcmp(groups[i].name, groupname) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int getGroupByID(int id, struct GroupData *group)
{
    struct GroupData groups[MAX_USERS];
    int groups_count = getGroups(groups);

    for (int i = 0; i < groups_count; i++)
    {
        if (groups[i].id == id)
        {
            *group = groups[i];
            return i;
        }
    }
    return -1;
}

int hasPermission(char *uuid, int perm)
{
    struct UserData user;
    struct GroupData group;
    getUserByUUID(uuid, &user);
    group = user.group;
    if (group.permissions[perm] == 1 || group.permissions[PERMISSION_ALL] == 1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void clearScreen()
{
    system("cls");
}

void init()
{
    printf("Inizialisiere...\n");
    strcpy(folder, "UserManager/");
    strcpy(config_file, folder);
    strcpy(users_file, folder);
    strcpy(groups_file, folder);
    strcpy(passwordsfolder, folder);
    strcpy(analytics_file, folder);
    strcpy(todo_file, folder);
    strcpy(password_manager_folder, folder);

    strcat(passwordsfolder, "password_lists/");
    strcat(config_file, "config.txt");
    strcat(users_file, "users.txt");
    strcat(groups_file, "groups.txt");
    strcat(standart_passwords_file, passwordsfolder);
    strcat(standart_passwords_file, "standart.txt");
    strcat(analytics_file, "analytics.txt");
    strcat(todo_file, "todo.txt");
    strcat(password_manager_folder, "password_manager/");
    showProgress(1, 10);
    if (!folderExists(folder))
    {
        mkdir(folder);
    }
    if (!fexists(config_file))
    {
        fcreate(config_file);
        sleep(1); // Wartet 1 Sekunde, da die Datei ein wenig Zeit brauch um sich zu erstellen
        resetConfig();
        showProgress(2, 10);
    }
    if (!fexists(users_file))
    {
        fcreate(users_file);
    }
    if (!fexists(groups_file))
    {
        fcreate(groups_file);
        sleep(1);
        showProgress(4, 10);
    }
    if (!fexists(analytics_file))
    {
        fcreate(analytics_file);
        sleep(1); // Wartet 1 Sekunde, da die Datei ein wenig Zeit brauch um sich zu erstellen
        resetAnalytics();
        showProgress(5, 10);
    }
    if (!fexists(todo_file))
    {
        fcreate(todo_file);
    }
    if (!folderExists(passwordsfolder))
    {
        mkdir(passwordsfolder);
    }
    if (!folderExists(password_manager_folder))
    {
        mkdir(password_manager_folder);
    }
    if (!fexists(standart_passwords_file))
    {
        fcreate(standart_passwords_file);
        sleep(1);
        writeFile("12345:123456:123456789:test1:password:12345678:zinch:g_czechout:asdf:qwerty:1234567890:1234567:Aa123456.:iloveyou:1234:abc123:111111:123123:dubsmash:test:princess:qwertyuiop:sunshine:BvtTest123:11111:ashley:00000:000000:-password1:monkey:livetest:55555:soccer:charlie:asdfghjkl:654321:family:michael:123321:football:baseball:q1w2e3r4t5y6:nicole:jessica:purple:shadow:hannah:chocolate:michelle:daniel:maggie:qwerty123:hello:112233:jordan:igger:666666:987654321:uperman:12345678910:summer:1q2w3e4r5t:fitness:bailey:zxcvbnm:fuckyou:121212:buster:butterfly:dragon:jennifer:amanda:justin:cookie:basketball:shopping:pepper:joshua:hunter:ginger:matthew:abcd1234:taylor:samantha:whatever:andrew:1qaz2wsx3edc:thomas:jasmine:animoto:madison:987654321:54321:flower:Password:maria:babygirl:lovely:sophie:Chegg123:computer:qwe123:anthony:1q2w3e4r:peanut:bubbles:asdasd:qwert:1qaz2wsx:pakistan:123qwe:liverpool:elizabeth:harley:chelsea:familia:yellow:william:george:7777777:loveme:123abc:letmein:oliver:batman:cheese:banana:testing:secret:angel:friends:jackson:aaaaaa:softball:chicken:lauren:andrea:welcome:asdfgh:robert:orange:Testing1:pokemon:555555:melissa:morgan:123123123:qazwsx:diamond:brandon:jesus:mickey:olivia:changeme:danielle:victoria:gabriel:123456a:0.00000000:loveyou:hockey:freedom:azerty:snoopy:skinny:myheritage:qwerty1:159753:forever:iloveu:killer:joseph:master:mustang:hellokitty:school:Password1:patrick:blink182:tinkerbell:rainbow:nathan:cooper:onedirection:alexander:jordan23:lol123:jasper:junior:q1w2e3r4:222222:11111111:benjamin:jonathan:passw0rd:123456789:a123456:samsung:123:love123", standart_passwords_file);
        showProgress(6, 10);
    }

    // Erstellt die PasswortManager Dateien, wenn ein Benutzer fehlt
    struct UserData users[MAX_USERS];
    int user_amount = getUsers(users);
    char path[100];
    for (int i = 0; i < user_amount; i++)
    {
        strcpy(path, password_manager_folder);
        strcat(path, users[i].uuid);
        strcat(path, ".txt");
        if (!fexists(path))
        {
            fcreate(path);
        }
    }
    showProgress(7, 10);
    // Erstellt die Gruppe Member wenn sie nicht exestiert
    struct GroupData groups[MAX_GROUPS];
    int amount = getGroups(groups);
    if (amount < 1)
    {
        int permissions[MAX_PERMISSIONS];
        memset(permissions, 0, sizeof(permissions));
        permissions[PERMISSION_ALL] = 1;
        createGroup("Administrator", permissions, 0);
    }

    // Erstellt die Gruppe Administrator wenn sie nicht exestiert
    if (amount < 2)
    {
        int permissions[MAX_PERMISSIONS];
        memset(permissions, 0, sizeof(permissions));
        createGroup("Member", permissions, 0);
    }

    // Loescht alle TODO Listen von einem Benutzer, wenn er nicht mehr exestiert
    struct TodoData todos[MAX_TODOS];
    int todo_amount = getTodos(todos);
    for (int i = 0; i < todo_amount; i++)
    {
        struct TodoData todo = todos[i];
        struct UserData user = todo.user;
        if (!UserExists(user.username))
        {
            deleteTodo(todo.uuid);
        }
    }
    showProgress(8, 10);
    // Weist den Benutzern, die in einer Gruppe sind, die nicht mehr exestiert, die Gruppe Members zu
    for (int i = 0; i < user_amount; i++)
    {
        if (!GroupExists(users[i].group.name))
        {
            struct GroupData group;
            getGroupByID(1, &group);
            users[i].group = group;
            saveUser(users[i]);
        }
    }
    showProgress(10, 10);
    sleep(1);
}

void writeFile(char *str, char *path)
{
    FILE *stream = fopen(path, "w");
    fwrite(str, 1, strlen(str), stream);
    fclose(stream);
}

void readFile(char *str, char *path, int len)
{
    FILE *stream = fopen(path, "r");
    fgets(str, len, stream);
    fclose(stream);
}

void appendFile(char *str, char *path)
{
    FILE *stream = fopen(path, "a");
    fwrite(str, 1, strlen(str), stream);
    fclose(stream);
}

int fexists(const char *fileName)
{
    FILE *file;
    if ((file = fopen(fileName, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

int fcreate(const char *fileName)
{
    FILE *file = fopen(fileName, "w");
    if (file != NULL)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

int fdelete(const char *fileName)
{
    return remove(fileName);
}

int folderExists(const char *folderName)
{
    DIR *dir = opendir(folderName);
    if (dir)
    {
        closedir(dir);
        return 1;
    }
    return 0;
}

void showAnalytics()
{
    do
    {
        clearScreen();
        int analytics[MAX_ANALYTICS];
        getAnalytics(analytics);

        printf("Analytics: \n\n");
        printf("Benutzer erstellt: %d\n", analytics[ANALYTICS_CREATE_USER]);
        printf("Benutzer geloescht: %d\n", analytics[ANALYTICS_DELETE_USER]);
        printf("Gruppe erstellt: %d\n", analytics[ANALYTICS_CREATE_GROUP]);
        printf("Gruppe geloescht: %d\n", analytics[ANALYTICS_DELETE_GROUP]);
        printf("Anmeldungen: %d\n", analytics[ANALYTICS_LOGINS]);
        printf("TODO Liste erstellt: %d\n", analytics[ANALYTICS_CREATE_TODO]);
        printf("\n\n");
        printf("[0] Zurueck zum Hauptmenue\n");
        printf("[1] Analytics loeschen\n");
        printf("# ");
        char opt = getch();

        switch (opt)
        {
        case '0':
            return;
            break;
        case '1':
            resetAnalytics();
            break;
        }
    } while (1);
}

void addAnalytic(int key)
{
    int analytics[MAX_ANALYTICS];
    getAnalytics(analytics);
    analytics[key]++;
    setAnalytics(analytics);
}

void setAnalytics(int *analytics)
{
    char data[MAX_ANALYTICS_FILE_SIZE];
    for (int i = 0; i < MAX_ANALYTICS; i++)
    {
        char analytics_str[10];
        sprintf(analytics_str, "%d", analytics[i]);
        strcat(data, analytics_str);
        strcat(data, ";");
    }
    writeFile(data, analytics_file);
}

int getAnalytics(int *analytics)
{
    char data[MAX_ANALYTICS_FILE_SIZE];
    char *data_split[MAX_ANALYTICS];
    readFile(data, analytics_file, MAX_ANALYTICS_FILE_SIZE);
    int amount = str_split(data, ";", data_split);
    for (int i = 0; i < amount; i++)
    {
        analytics[i] = atoi(data_split[i]);
    }
    return amount;
}

void resetAnalytics()
{
    int analytics[MAX_ANALYTICS];
    getAnalytics(analytics);
    for (int i = 0; i < MAX_ANALYTICS; i++)
    {
        analytics[i] = 0;
    }
    setAnalytics(analytics);
}

void createTodo(char *name, char *description, char *deadline)
{
    printf("Die TODO Liste wird erstellt...\n");
    char str[MAX_TODO_FILE_SIZE];
    struct TodoData todos[MAX_TODOS];
    int todo_amount = getTodos(todos);
    sprintf(str, "%d", todo_amount);
    strcat(str, ";");
    char uuid[37];
    generate_uuid(uuid);
    strcat(str, uuid);
    strcat(str, ";");
    strcat(str, current_user.uuid);
    strcat(str, ";");
    strcat(str, name);
    strcat(str, ";");
    strcat(str, description);
    strcat(str, ";");
    strcat(str, deadline);
    strcat(str, ":");
    appendFile(str, todo_file);
    addAnalytic(ANALYTICS_CREATE_TODO);
    printf("Die TODO Liste '%s' wurde erstellt.\n", name);
    printf("Druecke eine beliebige Taste um fortzufahren...");
    fflush(stdin);
    getch();
}

void deleteTodo(char *uuid)
{
    struct TodoData todos[MAX_TODOS];
    char data[MAX_USER_FILE_SIZE];
    memset(data, 0, sizeof(data));
    int todo_amount = getTodos(todos);

    struct TodoData todo;
    int index = 0;
    for (int i = 0; i < todo_amount; i++)
    {
        if (strcmp(todos[i].uuid, uuid) == 0)
        {
            todo = todos[i];
            index = i;
        }
    }

    todos[index] = todo;
    if (index >= 0)
    {
        for (int i = 0; i < todo_amount; i++)
        {
            if (i != index)
            {
                char str[10];
                sprintf(str, "%d", todos[i].id);
                strcat(data, str);
                strcat(data, ";");
                strcat(data, todos[i].uuid);
                strcat(data, ";");
                strcat(data, todos[i].user.uuid);
                strcat(data, ";");
                strcat(data, todos[i].name);
                strcat(data, ";");
                strcat(data, todos[i].description);
                strcat(data, ";");
                strcat(data, todos[i].deadline);
                strcat(data, ":");
            }
        }
        writeFile(data, todo_file);
    }
}

int getTodos(struct TodoData *todos)
{
    char data[MAX_TODO_FILE_SIZE];
    readFile(data, todo_file, MAX_TODO_FILE_SIZE);
    char *todosstr[MAX_TODOS];

    if (strstr(data, ":") != NULL)
    {
        int size = str_split(data, ":", todosstr);

        for (int i = 0; i < size; i++)
        {
            struct TodoData tododata;
            char *tododatastr[MAX_TODOS + 6];
            int amount = str_split(todosstr[i], ";", tododatastr);

            tododata.id = atoi(tododatastr[0]);
            strcpy(tododata.uuid, tododatastr[1]);
            struct UserData user;
            int error = getUserByUUID(tododatastr[2], &user);
            if (error >= 0)
            {
                tododata.user = user;
                strcpy(tododata.name, tododatastr[3]);
                strcpy(tododata.description, tododatastr[4]);
                strcpy(tododata.deadline, tododatastr[5]);
                for (int j = 0; j < amount - 6; j++)
                {
                    strcpy(tododata.entries[j], tododatastr[6 + j]);
                }
                tododata.entry_count = amount - 6;
                todos[i] = tododata;
            }
            else
            {
                return error;
            }
        }
        return size;
    }
    else
    {
        return 0;
    }
}

int getTodosByUserUUID(char *uuid, struct TodoData *todos)
{
    struct TodoData localtodos[MAX_TODOS];
    int todo_amount = getTodos(localtodos);
    if (todo_amount >= 0)
    {
        int j = 0;
        for (int i = 0; i < todo_amount; i++)
        {
            if (strcmp(localtodos[i].user.uuid, uuid) == 0)
            {
                todos[j] = localtodos[i];
                j++;
            }
        }
        return j;
    }
    else
    {
        return todo_amount;
    }
}

int changeTodo(char *uuid, char *mode)
{
    struct TodoData todos[MAX_TODOS];
    struct TodoData todo;
    int todo_amount = getTodos(todos);
    int index = getTodoByUUID(uuid, &todo);

    if (strcmp(mode, "name") == 0)
    {
        char name[MAX_TODO_NAME];
        int validinput = 1;
        int todo_exists = 0;
        do
        {
            if (!validinput)
            {
                printf("Der Name darf kein ':' und kein ';' enthalten: ");
            }
            else if (todo_exists)
            {
                printf("Es exestiert schon eine TODO Liste mit diesem Namen:");
            }
            else
            {
                printf("Gib den neune Namen der TODO Liste ein: ");
            }
            fflush(stdin);
            fgets(name, MAX_TODO_NAME, stdin);
            str_trim(name);
            validinput = validate_format(name);
            todo_exists = todoExists(name);
        } while (!validinput || todo_exists);
        strcpy(todo.name, name);
    }
    else if (strcmp(mode, "addEntry") == 0)
    {
        char entry[MAX_TODO_ENTRY_LENGTH];
        int validinput = 1;
        do
        {
            if (validinput)
            {
                printf("Gib den Namen des Entrags ein: ");
            }
            else
            {
                printf("Der Name darf kein ':' und kein ';' enthalten: ");
            }
            fflush(stdin);
            fgets(entry, MAX_TODO_ENTRY_LENGTH, stdin);
            validinput = validate_format(entry);
            str_trim(entry);
            strcpy(todo.entries[todo.entry_count], entry);
            todo.entry_count++;
        } while (!validinput);
    }
    else if (strcmp(mode, "removeEntry") == 0)
    {
        int id = 0;
        int entryexists = 1;
        do
        {
            if (entryexists)
            {
                printf("Gib die ID des Eintrags ein, den du loeschen moechtest: ");
            }
            else
            {
                printf("Dieser Eintrag exestiert nicht, gib eine andere ID ein: ");
            }
            scanf(" %d", &id);
            entryexists = id <= todo.entry_count;
            if (entryexists)
            {
                for (int i = 0; i < todo.entry_count; i++)
                {
                    if (i > id)
                    {
                        strcpy(todo.entries[i - 1], todo.entries[i]);
                    }
                }
            }
            todo.entry_count--;
        } while (!entryexists);
    }
    else if (strcmp(mode, "editEntry") == 0)
    {
        int validinput = 1;
        int entryexits = 1;
        int id = 0;
        do
        {
            if (entryexits)
            {
                printf("Gib die ID des Eintrags ein, den du bearbeiten moechtest: ");
            }
            else
            {
                printf("Dieser Eintrag exestiert nicht, gib eine andere ID ein: ");
            }
            scanf(" %d", &id);
            entryexits = id <= todo.entry_count - 1 && 0 <= id;
        } while (!entryexits);
        char name[MAX_TODO_ENTRY_LENGTH];
        do
        {
            if (validinput)
            {
                printf("Gib den neuen Namen des Entrags ein: ");
            }
            else
            {
                printf("Der Name darf kein ':' und kein ';' enthalten: ");
            }
            fflush(stdin);
            fgets(name, MAX_TODO_ENTRY_LENGTH, stdin);
            validinput = validate_format(name);
            str_trim(name);
        } while (!validinput);
        strcpy(todo.entries[id], name);
    }
    saveTodo(todo, index);
}

int getTodoByUUID(char *uuid, struct TodoData *todo)
{
    struct TodoData todos[MAX_TODOS];
    int todo_count = getTodos(todos);

    for (int i = 0; i < todo_count; i++)
    {
        if (strcmp(todos[i].uuid, uuid) == 0)
        {
            *todo = todos[i];
            return i;
        }
    }
    return -1;
}

int getTodoByID(int id, struct TodoData *todo)
{
    struct TodoData todos[MAX_TODOS];
    int todo_count = getTodos(todos);

    for (int i = 0; i < todo_count; i++)
    {
        if (todos[i].id == id)
        {
            *todo = todos[i];
            return i;
        }
    }
    return -1;
}

void saveTodo(struct TodoData todo, int index)
{
    struct TodoData todos[MAX_TODOS];
    char data[MAX_USER_FILE_SIZE];
    memset(data, 0, sizeof(data));
    int todo_amount = getTodos(todos);
    todos[index] = todo;
    if (index >= 0)
    {
        for (int i = 0; i < todo_amount; i++)
        {
            char str[10];
            sprintf(str, "%d", todos[i].id);
            strcat(data, str);
            strcat(data, ";");
            strcat(data, todos[i].uuid);
            strcat(data, ";");
            strcat(data, todos[i].user.uuid);
            strcat(data, ";");
            strcat(data, todos[i].name);
            strcat(data, ";");
            strcat(data, todos[i].description);
            strcat(data, ";");
            strcat(data, todos[i].deadline);
            for (int j = 0; j < todos[i].entry_count; j++)
            {
                strcat(data, ";");
                strcat(data, todos[i].entries[j]);
            }
            strcat(data, ":");
        }
        writeFile(data, todo_file);
    }
}

int todoExists(char *name)
{
    struct TodoData todos[MAX_TODOS];
    int amount = getTodos(todos);
    for (int i = 0; i < amount; i++)
    {
        if (strcmp(todos[i].name, name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void checkTodoDeadlines(struct TodoData *todos, int todo_amount, int *daysleft)
{
    for (int i = 0; i < todo_amount; i++)
    {
        if (strcmp(todos[i].deadline, "null") != 0)
        {
            daysleft[i] = checkDeadline(todos[i].deadline);
        }
    }
}

int getPasswordEntries(struct PasswordEntry *pes)
{
    char data[MAX_PM_FILE_SIZE];
    char rawdata[MAX_PM_FILE_SIZE];
    char path[200];

    strcpy(path, password_manager_folder);
    strcat(path, current_user.uuid);
    strcat(path, ".txt");
    readFile(data, path, MAX_PM_FILE_SIZE);

    zn_decrypt(data, current_user.password, rawdata);

    char *pestr[MAX_PM_PES];
    if (strstr(rawdata, ":") != NULL)
    {
        int size = str_split(rawdata, ":", pestr);
        for (int i = 0; i < size; i++)
        {
            struct PasswordEntry pe;
            char *pedatastr[10];
            str_split(pestr[i], ";", pedatastr);

            strcpy(pe.uuid, pedatastr[0]);
            strcpy(pe.name, pedatastr[1]);
            strcpy(pe.email, pedatastr[2]);
            strcpy(pe.password, pedatastr[3]);
            pes[i] = pe;
        }
        return size;
    }
    else
    {
        return 0;
    }
}

void addPasswordEntry()
{
    struct PasswordEntry pes[MAX_PM_PES];
    if (getPasswordEntries(pes) >= MAX_PM_PES)
    {
        printf("Es kann kein weiterer Eintrag erstellt werden, da die maximale Anzahl an Eintraegen erreicht ist.\n");
        printf("Druecke eine beliebige Taste um fortzufahren.\n");
        getch();
    }
    char name[MAX_PM_PE_NAME];
    char email[MAX_PM_PE_EMAIL];
    char password[MAX_PM_PE_PASSWORD];

    int validinput = 1;
    int input_empty = 0;
    do
    {
        if (validinput)
        {
            printf("Gib den Namen des Eintrages ein: ");
        }
        else
        {
            printf("Der Name darf kein ':' und ';' enthalten, gib einen anderen Namen ein: ");
        }
        fflush(stdin);
        fgets(name, MAX_PM_PE_NAME, stdin);
        if (strlen(name) == 0)
        {
            input_empty = 1;
        }
        else
        {
            input_empty = 0;
        }
        validinput = validate_format(name);
        str_trim(name);
    } while (!validinput || input_empty);

    validinput = 1;
    input_empty = 0;
    do
    {
        if (validinput)
        {
            printf("Gib die/den Email/Benutzername des Eintrages ein: ");
        }
        else
        {
            printf("Der/Die Email/Benutzername darf kein ':' und ';' enthalten, gib einen anderen Namen ein: ");
        }
        fflush(stdin);
        fgets(email, MAX_PM_PE_EMAIL, stdin);
        if (strlen(name) == 0)
        {
            input_empty = 1;
        }
        else
        {
            input_empty = 0;
        }
        validinput = validate_format(email);
        str_trim(email);
    } while (!validinput);

    int conf;
    validinput = 1;
    input_empty = 0;
    do
    {
        printf("Moechtest du den Passwortgenerator verwenden?[Y/N]: ");
        conf = getchar();
    } while (conf != 'Y' && conf != 'N');
    if (conf == 'Y')
    {
        showPasswordGenerator(password, MAX_PM_PE_PASSWORD);
    }
    else
    {
        do
        {
            fflush(stdin);
            int pwderror = getPassword("Gib das Passwort des Etrages ein", password, MAX_PM_PE_PASSWORD);
            if (!(pwderror >= 0))
            {
                return;
            }
            if (strlen(name) == 0)
            {
                input_empty = 1;
            }
            else
            {
                input_empty = 0;
            }
            str_trim(password);
        } while (input_empty);
    }

    clearScreen();
    char data[MAX_PM_FILE_SIZE];
    memset(data, 0, sizeof(data));
    printf("Passwort Eintrag wird erstellt...");
    printf("UUID wird generiert...");
    char uuid[MAX_UUID];
    generate_uuid(uuid);
    printf("UUID wurde generiert.");
    printf("UUID wird hinzugefuegt...");
    strcpy(data, uuid);
    strcat(data, ";");
    printf("-> Done\n");
    printf("Name wird hinzugefuegt...");
    strcat(data, name);
    strcat(data, ";");
    printf("-> Done\n");
    printf("Email wird hinzugefuegt...");
    strcat(data, email);
    strcat(data, ";");
    printf("-> Done\n");
    printf("Passwort wird hinzugefuegt...");
    strcat(data, password);
    printf("-> Done\n");
    strcat(data, ":");

    printf("Druecke eine belibige Taste um fortzufahren...");
    fflush(stdin);
    getchar();
    char path[200];
    strcpy(path, password_manager_folder);
    strcat(path, current_user.uuid);
    strcat(path, ".txt");

    char encdata[MAX_PM_FILE_SIZE];
    char rawdata[MAX_PM_FILE_SIZE];
    readFile(path, encdata, MAX_PM_FILE_SIZE);

    zn_decrypt(encdata, current_user.password, rawdata);
    strcat(rawdata, data);
    zn_encrypt(rawdata, current_user.password, encdata);
    writeFile(encdata, path);
}

void editPasswordEntry()
{
    struct PasswordEntry entries[MAX_PM_PES];
    int pe_amount = getPasswordEntries(entries);
    int entryexists = 1;
    int id = 0;
    int pwd_visible = 0;
    do
    {
        if (entryexists)
        {
            printf("Gib die ID des Eintrages ein: ");
        }
        else
        {
            printf("Dieser Eintrag exestiert nicht, gib eine andere ID ein: ");
        }
        scanf(" %d", &id);

        entryexists = strcmp(entries[id].uuid, "") == 0 ? 0 : 1;
    } while (!entryexists);

    struct PasswordEntry entry = entries[id];

    while (1)
    {
        clearScreen();
        char cenzored_password[MAX_PASSWORD];
        if (!pwd_visible)
        {
            strcpy(cenzored_password, "");
            for (int i = 0; i < strlen(entry.password); i++)
            {
                strcat(cenzored_password, "*");
            }
        }
        printf("------------%s------------\n", entry.name);
        printf("Email:    %s\n", entry.email);
        printf("Password: %s\n", pwd_visible == 0 ? cenzored_password : entry.password);
        printf("--------------------------\n\n\n");

        printf("[0] Zurueck zur Passwortverwaltung\n");
        printf("[1] Name bearbeiten\n");
        printf("[2] Email bearbeiten\n");
        printf("[3] Passwort bearbeiten\n");
        printf("[4] Passwort anzeigen\n");
        fflush(stdin);
        int in = getch();

        switch (in)
        {
        case '0':
            return;
            break;
        case '1':
            char name[MAX_PM_PE_NAME];
            int validinput = 1;
            do
            {
                if (validinput)
                {
                    printf("Gib den neuen Namen des Eintrages ein: ");
                }
                else
                {
                    printf("Der Name darf kein ':' und kein ';' enthalten: ");
                }
                fgets(name, MAX_PM_PE_NAME, stdin);
                validinput = validate_format(name);
                str_trim(name);
            } while (!validinput);
            strcpy(entry.name, name);
            break;
        case '2':
            char email[MAX_PM_PE_EMAIL];
            validinput = 1;
            do
            {
                if (validinput)
                {
                    printf("Gib die neue Email des Eintrages ein: ");
                }
                else
                {
                    printf("Die Email darf kein ':' und kein ';' enthalten: ");
                }
                fgets(email, MAX_PM_PE_EMAIL, stdin);
                validinput = validate_format(email);
                str_trim(email);
            } while (!validinput);

            strcpy(entry.email, email);
            break;
        case '3':
            char password[MAX_PM_PE_PASSWORD];
            int conf;
            do
            {
                printf("Moechtest du den Passwortgenerator verwenden?[Y/N]: ");
                conf = getchar();
            } while (conf != 'Y' && conf != 'N');
            if (conf == 'Y')
            {
                showPasswordGenerator(password, MAX_PM_PE_PASSWORD);
            }
            else
            {
                validinput = 1;
                do
                {
                    fflush(stdin);
                    getPassword("Gib das neue Passwort des Eintrages ein", password, MAX_PM_PE_PASSWORD);
                    str_trim(password);
                } while (!validinput);
            }
            strcpy(entry.password, password);
            break;
        case '4':
            if (pwd_visible)
            {
                pwd_visible = 0;
            }
            else
            {
                pwd_visible = 1;
            }
            break;
        }
        char text[MAX_PM_FILE_SIZE];
        memset(text, 0, sizeof(text));
        struct PasswordEntry pes[MAX_PM_PES];
        int entry_amount = getPasswordEntries(pes);
        pes[id] = entry;
        for (int i = 0; i < entry_amount; i++)
        {
            strcpy(text, pes[i].uuid);
            strcat(text, ";");
            strcat(text, pes[i].name);
            strcat(text, ";");
            strcat(text, pes[i].email);
            strcat(text, ";");
            strcat(text, pes[i].password);
            strcat(text, ":");
        }
        char rawdata[MAX_PM_FILE_SIZE];
        char data[MAX_PM_FILE_SIZE];
        char path[200];
        strcpy(path, password_manager_folder);
        strcat(path, current_user.uuid);
        strcat(path, ".txt");

        strcpy(rawdata, text);
        zn_encrypt(rawdata, current_user.password, data);
        writeFile(data, path);
    }
}

void deletePasswordEntry()
{
    struct PasswordEntry entries[MAX_PM_PES];
    int pe_amount = getPasswordEntries(entries);
    int entryexists = 1;
    int id = 0;
    do
    {
        if (entryexists)
        {
            printf("Gib die ID des Eintrages ein: ");
        }
        else
        {
            printf("Dieser Eintrag exestiert nicht, gib eine andere ID ein: ");
        }
        scanf(" %d", &id);

        entryexists = strcmp(entries[id].uuid, "") == 0 ? 0 : 1;
    } while (!entryexists);

    char rawdata[MAX_PM_FILE_SIZE];
    memset(rawdata, 0, sizeof(rawdata));
    struct PasswordEntry pes[MAX_PM_PES];
    int entry_amount = getPasswordEntries(pes);

    for (int i = 0; i < entry_amount; i++)
    {
        if (i != id)
        {
            strcpy(rawdata, pes[i].uuid);
            strcat(rawdata, ";");
            strcat(rawdata, pes[i].name);
            strcat(rawdata, ";");
            strcat(rawdata, pes[i].email);
            strcat(rawdata, ";");
            strcat(rawdata, pes[i].password);
            strcat(rawdata, ":");
        }
    }
    char path[200];
    strcpy(path, password_manager_folder);
    strcat(path, current_user.uuid);
    strcat(path, ".txt");

    char data[MAX_PM_FILE_SIZE];
    zn_encrypt(rawdata, current_user.password, data);
    writeFile(data, path);
}

int getConfig(struct ConfigData *config)
{
    char data[MAX_CONFIG_FILE_SIZE];
    char *data_split[MAX_CONFIG];
    memset(data, 0, sizeof(data));
    readFile(data, config_file, MAX_ANALYTICS_FILE_SIZE);
    if (strstr(data, ";") == NULL)
    {
        return 0;
    }
    else
    {
        int amount = str_split(data, ";", data_split);
        strcpy(config->autologin, data_split[0]);
        config->running_retry_passwort_timeout = atoi(data_split[1]);
        config->running_passwort_trys = atoi(data_split[2]);
        config->retry_passwort_timeout = atoi(data_split[3]);
        config->password_trys = atoi(data_split[4]);
        strcpy(config->password_deadline, data_split[4]);
        return amount;
    }
}

void setConfig(struct ConfigData config)
{
    char data[MAX_CONFIG_FILE_SIZE];
    memset(data, 0, sizeof(data));
    strcpy(data, config.autologin);
    strcat(data, ";");
    char str[10];
    sprintf(str, "%d", config.running_retry_passwort_timeout);
    strcat(data, str);
    strcat(data, ";");
    sprintf(str, "%d", config.running_passwort_trys);
    strcat(data, str);
    strcat(data, ";");
    sprintf(str, "%d", config.retry_passwort_timeout);
    strcat(data, str);
    strcat(data, ";");
    sprintf(str, "%d", config.password_trys);
    strcat(data, str);
    strcat(data, ";");
    strcat(data, config.password_deadline);
    strcat(data, ";");
    writeFile(data, config_file);
}

void resetConfig()
{
    struct ConfigData config;
    strcpy(config.autologin, "null");
    config.running_retry_passwort_timeout = 0;
    config.retry_passwort_timeout = 5;
    config.password_trys = 3;
    strcpy(config.password_deadline, "null");
    setConfig(config);
}

void getDate(char *date)
{
    int valid_input = 1;
    int day, month, year, hours, minutes, seconds;
    char daystr[3];
    char monthstr[3];
    char yearstr[5];
    char hoursstr[3];
    char minutesstr[3];
    char secondsstr[3];

    //----------------------Aktuelles Datum bekommen----------------------
    time_t now;
    struct tm *current_time;

    time(&now);
    current_time = localtime(&now);

    int currday = current_time->tm_mday;
    int currmonth = current_time->tm_mon + 1;
    int curryear = current_time->tm_year + 1900;
    int currhours = current_time->tm_hour;
    int currminutes = current_time->tm_min;
    int currseconds = current_time->tm_sec;
    //----------------------Aktuelles Datum bekommen----------------------

    int param_amount = 6;
    valid_input = 1;
    do
    {
        if (param_amount != 6)
        {
            printf("Wrong format. Please enter the date in the format dd/mm/yyyy-hh.mm.ss: ");
        }
        else if (!valid_input)
        {
            printf("The values are not possible, maybe you have a clock: ");
        }
        else
        {
            printf("Enter a completion date for your TODO list(dd/mm/yyyy-hh.mm.ss): ");
        }

        param_amount = scanf(" %d/%d/%d-%d.%d.%d", &day, &month, &year, &hours, &minutes, &seconds);
        valid_input = valid_input = (year > curryear || (year == curryear && month > currmonth) || (year == curryear && month == currmonth && day > currday) ||
                                     (year == curryear && month == currmonth && day == currday && hours > currhours) ||
                                     (year == curryear && month == currmonth && day == currday && hours == currhours && minutes > currminutes) ||
                                     (year == curryear && month == currmonth && day == currday && hours == currhours && minutes == currminutes && seconds >= currseconds)) &&
                                    (day >= 1 && day <= 31) && (month >= 1 && month <= 12) && (hours >= 0 && hours <= 23) && (minutes >= 0 && minutes <= 59) && (seconds >= 0 && seconds <= 59) &&
                                    (year <= 9999);
    } while (param_amount != 6 || !valid_input);

    sprintf(daystr, "%d", day);
    sprintf(monthstr, "%d", month);
    sprintf(yearstr, "%d", year);
    sprintf(hoursstr, "%d", hours);
    sprintf(minutesstr, "%d", minutes);
    sprintf(secondsstr, "%d", seconds);

    strcpy(date, daystr);
    strcat(date, "/");
    strcat(date, monthstr);
    strcat(date, "/");
    strcat(date, yearstr);
    strcat(date, "-");
    strcat(date, hoursstr);
    strcat(date, ".");
    strcat(date, monthstr);
    strcat(date, ".");
    strcat(date, secondsstr);
}

int getPassword(char *message, char *password, int password_len)
{
    printf("%s(ESC to go back and TAB to show and hide): ", message);
    fflush(stdout);
    int i = 0;
    int visible = 0;
    while (i < password_len)
    {
        fflush(stdin);
        int c = getch();
        if (c == 13)
        {
            break;
        }
        else if (c == 8 || c == 127)
        {
            if (i > 0)
            {
                i--;
                password[i] = '\0';
                printf("\b \b");
                fflush(stdout);
            }
        }
        else if (c == 27)
        {
            return -1;
        }
        else if (c == 9)
        {
            switch (visible)
            {
            case 1:
                visible = 0;
                printf("\033[2K\r");
                printf("%s(ESC to go back and TAB to show and hide): ", message);
                for (int j = 0; j < i; j++)
                {
                    printf("*");
                }
                break;
            case 0:
                visible = 1;
                printf("\033[2K\r");
                printf("%s(ESC to go back and TAB to show and hide): ", message);
                for (int j = 0; j < i; j++)
                {
                    printf("%c", password[j]);
                }
                break;
            }
        }
        else if (c >= 33 && 126 >= c)
        {
            password[i++] = c;
            if (visible)
            {
                printf("%c", c);
            }
            else
            {
                printf("*");
            }
            fflush(stdout);
        }
    }
    password[i] = '\0';
    printf("\n");
}

int str_tolower(char *str)
{
    for (int i = 0; i < strlen(str); i++)
    {
        if (str[i] >= 'A' && str[i] <= 'Z')
        {
            str[i] = (int)str[i] + 32;
        }
    }
}

void str_trim(char *array)
{
    int alen = strlen(array) - 1;
    if (array[alen] == '\n')
    {
        array[alen] = '\0';
    }
}

int str_split(char *str, char *delimiter, char **array)
{
    char *token = strtok(str, delimiter);
    int index = 0;
    while (token != NULL)
    {
        array[index++] = token;
        token = strtok(NULL, delimiter);
    }
    return index;
}

void char_to_str(char ch, char *str)
{
    str[0] = ch;
    str[1] = '\0';
}

int validate_format(char *str)
{
    if (strstr(str, ":") != NULL || strstr(str, ";") != NULL)
    {
        return 0;
    }
    return 1;
}

int validate_email(char *email)
{
    int i, at_position = -1, dot_position = -1;

    // Überpruefe, ob das '@'-Zeichen und das '.'-Zeichen vorhanden sind
    for (i = 0; email[i] != '\0'; i++)
    {
        if (email[i] == '@')
        {
            at_position = i;
        }
        else if (email[i] == '.')
        {
            dot_position = i;
        }
    }

    if (at_position == -1 || dot_position == -1)
    {
        return 0;
    }

    // Überpruefe, ob das '@'-Zeichen vor dem '.'-Zeichen kommt und es mindestens 1 Zeichen zwischen beiden gibt
    if (at_position >= dot_position - 1 || dot_position >= strlen(email) - 1)
    {
        return 0;
    }

    return 1;
}

int validate_phone_number(char *phone_number)
{
    int i, digit_count = 0;

    // Zaehle die Anzahl der Ziffern in der Telefonnummer
    for (i = 0; phone_number[i] != '\0'; i++)
    {
        if (phone_number[i] >= '0' && phone_number[i] <= '9')
        {
            digit_count++;
        }
    }

    // Überpruefe, ob die Telefonnummer mindestens 6 und hoechstens 14 Ziffern enthaelt
    if (digit_count < 6 || digit_count > 14)
    {
        return 0;
    }

    return 1;
}

int checkDeadline(char *deadline)
{
    time_t now;
    time(&now);
    struct tm *current_time = localtime(&now);
    time_t current_seconds = mktime(current_time);

    char *deadline_split[MAX_TODO_DEATHLINE];
    char *date_split[10];
    char *time_split[10];
    str_split(deadline, "-", deadline_split);
    str_split(deadline_split[0], "/", date_split);
    str_split(deadline_split[1], ".", time_split);

    int day = atoi(date_split[0]);
    int month = atoi(date_split[1]);
    int year = atoi(date_split[2]);
    int hours = atoi(time_split[0]);
    int minutes = atoi(time_split[1]);
    int seconds = atoi(time_split[2]);

    // Umwandlung der zu ueberpruefenden Zeit in Sekunden
    struct tm check_time = {0};
    check_time.tm_year = year - 1900;
    check_time.tm_mon = month - 1;
    check_time.tm_mday = day;
    check_time.tm_hour = hours;
    check_time.tm_min = minutes;
    check_time.tm_sec = seconds;
    time_t check_seconds = mktime(&check_time);
    int days_diff = (current_seconds - check_seconds) / 86400;
    return days_diff;
}

void zn_encrypt(const char *rawdata, char *password, char *data)
{
    memset(data, 0, sizeof(data));
    char firstHash[MAX_HASH];
    char secondHash[MAX_HASH];
    char hash[MAX_HASH];
    sha256(password, firstHash);
    md5(firstHash, secondHash);
    sha256(secondHash, hash);

    for (int i = 0; i < strlen(rawdata); i++)
    {
        for (int j = 0; j < strlen(hash); j++)
        {
            if (j % 2 == 0)
            {
                data[i] = rawdata[i] + (41 - hash[j]);
            }
            else
            {
                data[i] = rawdata[i] - (41 - hash[j]);
            }
        }
    }
    data[strlen(rawdata)] = '\0';
}

void zn_decrypt(const char *data, char *password, char *rawdata)
{
    char firstHash[MAX_HASH];
    char secondHash[MAX_HASH];
    char hash[MAX_HASH];
    sha256(password, firstHash);
    md5(firstHash, secondHash);
    sha256(secondHash, hash);
    memset(rawdata, 0, sizeof(rawdata));
    for (int i = 0; i < strlen(data); i++)
    {
        for (int j = 0; j < strlen(hash); j++)
        {
            if (j % 2 == 0)
            {
                rawdata[i] = data[i] - (41 - hash[j]);
            }
            else
            {
                rawdata[i] = data[i] + (41 - hash[j]);
            }
        }
    }
    rawdata[strlen(data)] = '\0';
}

// void hash_password(char *password, char *hash) {
// char hash1[SHA256_SIZE];
// char hash2[MD5_SIZE];
// sha256(password, hash1);
// md5(hash1, hash2);
// sha256(hash2, hash);
// }

int checkPasswordStrength(char *password)
{
    int length = strlen(password);
    int score = 0;

    // Pruefe die Laenge des Passworts
    if (length < 8)
    {
        score += 5;
    }
    else if (length >= 8 && length <= 12)
    {
        score += 10;
    }
    else
    {
        score += 15;
    }

    int upper_case = 0, lower_case = 0;
    for (int i = 0; i < length; i++)
    {
        if (password[i] >= 'A' && password[i] <= 'Z')
        {
            upper_case = 1;
        }
        else if (password[i] >= 'a' && password[i] <= 'z')
        {
            lower_case = 1;
        }
    }
    if (upper_case && lower_case)
    {
        score += 20;
    }

    int digits = 0;
    for (int i = 0; i < length; i++)
    {
        if (password[i] >= '0' && password[i] <= '9')
        {
            digits = 1;
            break;
        }
    }
    if (digits)
    {
        score += 20;
    }

    int special_chars = 0;
    for (int i = 0; i < length; i++)
    {
        if (!((password[i] >= 'A' && password[i] <= 'Z') || (password[i] >= 'a' && password[i] <= 'z') || (password[i] >= '0' && password[i] <= '9')))
        {
            special_chars = 1;
            break;
        }
    }
    if (special_chars)
    {
        score += 20;
    }
    return score;
}

int password_common(char *password)
{
    char *common_passwords[200];
    char lpwd[MAX_PASSWORD];
    int length;
    char line[2000];
    strcpy(lpwd, password);
    str_tolower(lpwd);

    readFile(line, standart_passwords_file, 2000);
    if (strstr(line, ":") != NULL)
    {
        int index = str_split(line, ":", common_passwords);
        for (int i = 0; i < index; i++)
        {
            str_tolower(common_passwords[i]);
            if (strcmp(lpwd, common_passwords[i]) == 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

void generate_uuid(char *uuid_str)
{
    sprintf(uuid_str, "%x-%x-%x-%x-%x",
            rand() & 0xffff, rand() & 0xffff,
            rand() & 0xffff,
            rand() & 0xffff,
            rand() & 0xffff);
}

void initRandom()
{
    srand(time(NULL));
}

int random(int min, int max)
{
    int num = 0;
    do
    {
        num = rand() % max + min;
    } while (num < min || num > max);
    return num;
}

void showProgress(int progress, int max)
{
    float percent = (float)progress / max;
    int fill_count = max * percent;
    printf("\r");
    for (int i = 0; i < max; i++)
    {
        if (i < fill_count)
        {
            printf("#");
        }
        else
        {
            printf("-");
        }
    }
    printf(" [Progress: %.2f%]", percent * 100);
}
