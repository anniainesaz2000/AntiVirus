#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

// Part 1a
#define MAX_FILENAME_LENGTH 256
#define MIN(a, b) ((a) < (b) ? (a) : (b))

char sigFileName[MAX_FILENAME_LENGTH] = "signatures-L";

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef struct fun_desc {
    char *name;
    void (*fun)();
} fun_desc;

//functions declerations
void detect_virus(char *buffer, unsigned int size, link *virus_list);
int is_signature_in_buffer(const char *buffer, size_t buffer_size, unsigned char *sig, size_t sig_size);
void detect_signature_Offset(char *buffer, unsigned int size, link *virus_list);

// Global variables
link *my_list = NULL;
FILE *suspected_file = NULL;
char *suspected_file_name;
char *suspected_buffer = NULL;
unsigned int file_size;
bool isLittleIndian;

void SetSigFileName() {
    printf("Enter new signature file name: ");
    fgets(sigFileName, MAX_FILENAME_LENGTH, stdin);

    // Remove newline character at the end if present
    size_t len = strlen(sigFileName);
    if (len > 0 && sigFileName[len - 1] == '\n') {
        sigFileName[len - 1] = '\0';
    }
}

// Function to read 16-bit integer in big-endian format
uint16_t read_uint16_big_endian(FILE *file) {
    uint8_t bytes[2];
    if (fread(bytes, 1, 2, file) != 2) {
        perror("Failed to read 2 bytes for uint16_t");
        return 0;
    }
    return (bytes[0] << 8) | bytes[1];
}

// Function to read 16-bit integer in little-endian format
uint16_t read_uint16_little_endian(FILE *file) {
    uint8_t bytes[2];
    if (fread(bytes, 1, 2, file) != 2) {
        perror("Failed to read 2 bytes for uint16_t");
        return 0;
    }
    return (bytes[1] << 8) | bytes[0];
}

virus* readVirus(FILE* file, bool is_little_endian) {
    virus* v = (virus*)malloc(sizeof(virus));
    if (v == NULL) {
        perror("Failed to allocate memory for virus struct");
        return NULL;
    }

    // Read the signature size based on endianness
    if (is_little_endian) {
        v->SigSize = read_uint16_little_endian(file);
    } else {
        v->SigSize = read_uint16_big_endian(file);
    }
    
    if (v->SigSize == 0) { // Check for end of file
        free(v);
        return NULL;
    }

    // Read the virus name
    if (fread(v->virusName, 1, 16, file) != 16) {
        perror("Failed to read the virus name");
        free(v);
        return NULL;
    }

    // Allocate memory for the signature
    v->sig = (unsigned char*)malloc(v->SigSize * sizeof(unsigned char));
    if (v->sig == NULL) {
        perror("Failed to allocate memory for signature");
        free(v);
        return NULL;
    }

    // Read the signature
    if (fread(v->sig, 1, v->SigSize, file) != v->SigSize) {
        perror("Failed to read the signature");
        free(v->sig);
        free(v);
        return NULL;
    }

    return v;
}

void printVirus(virus* v) {
    if (v == NULL) {
        return;
    }

    printf("Virus name: %s\n", v->virusName);
    printf("Virus signature length: %u\n", v->SigSize);
    printf("Virus signature: ");

    for (int i = 0; i < v->SigSize; i++) {
        printf("%02X ", v->sig[i]);
    }

    printf("\n");
}

bool isMagicNumberOK(FILE* file) {
    unsigned char buffer[4];
    if (fread(buffer, 1, 4, file) != 4) {
        return false;
    }

    if (memcmp(buffer, "VIRL", 4) == 0) {
        isLittleIndian = true;
        return true;
    }

    if (memcmp(buffer, "VIRB", 4) == 0) {
        isLittleIndian = false;
        return true;
    }

    return false;
}

// Part 1b
void list_print(link *virus_list, FILE *file) {
    while (virus_list != NULL) {
        printVirus(virus_list->vir);
        virus_list = virus_list->nextVirus;
    }
}

link* list_append(link* virus_list, virus* data) {
    link* newLink = (link*)malloc(sizeof(link));
    if (newLink == NULL) {
        perror("Failed to allocate memory for new link");
        return virus_list;
    }
    newLink->vir = data;
    newLink->nextVirus = NULL;

    if (virus_list == NULL) {
        return newLink;
    }

    link* last = virus_list;
    while (last->nextVirus != NULL) {
        last = last->nextVirus;
    }
    last->nextVirus = newLink;
    return virus_list;
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link* temp = virus_list;
        virus_list = virus_list->nextVirus;
        free(temp->vir->sig);
        free(temp->vir);
        free(temp);
    }
}

void PrintSignatures() {
    list_print(my_list, stdout);
}

void LoadSignatures() {
    FILE *file = fopen(sigFileName, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    if (!isMagicNumberOK(file)) {
        fclose(file);
        printf("Invalid magic number\n");
        return;
    }

    printf("Boolean value: %s\n", isLittleIndian ? "true" : "false");

    while (true) {
        virus *v = readVirus(file, isLittleIndian);
        if (v == NULL) {
            break;
        }
        my_list = list_append(my_list, v);
    }

    fclose(file);
}

void DetectViruses() {
    if (suspected_buffer != NULL) {
        detect_virus(suspected_buffer, MIN(10000, file_size), my_list);
    } else {
        printf("No suspected buffer loaded\n");
    }
}

void FixFile() {
    detect_signature_Offset(suspected_buffer,  MIN(10000, file_size), my_list);
    my_list = NULL;
}

void Quit() {
    list_free(my_list);
    if (suspected_buffer != NULL) {
        free(suspected_buffer);
    }
    if (suspected_file != NULL) {
        fclose(suspected_file);
    }
    exit(0);
}

//Part 1c

void detect_virus(char *buffer, unsigned int size, link *virus_list){
    while(virus_list != NULL){
        int index = is_signature_in_buffer(buffer, size, virus_list->vir->sig,virus_list->vir->SigSize);
        if(index >= 0){
            printf("The starting byte location: %d\n", index);
            printf("The virus name: %s\n", virus_list->vir->virusName);
            printf("The size of the virus signature: %d\n", virus_list->vir->SigSize);
        }
        virus_list = virus_list->nextVirus;
    }
}

int is_signature_in_buffer(const char *buffer, size_t buffer_size, unsigned char *sig, size_t sig_size) {
    // Loop through buffer and compare segments with sig
    for (size_t i = 0; i <= buffer_size - sig_size; i++) {
        if (memcmp(&buffer[i], sig, sig_size) == 0) {
            return i; // Signature found in buffer
        }
    }
    return -1; // Signature not found in buffer
}

void copy_file_to_buffer(){
    suspected_buffer = (char *)malloc(10000 * sizeof(char));
    if (suspected_buffer == NULL) {
        perror("Failed to allocate buffer");
        fclose(suspected_file);
        exit(1);
    }

    // Read the file content into the buffer
    fread(suspected_buffer, 1, 10000, suspected_file);
}

//Part 2b

void neutralize_virus(const char *fileName, int signatureOffset) {
    FILE *file = fopen(fileName, "r+b");
    if (!file) {
        perror("Failed to open file");
        exit(1);
    }

    if (fseek(file, signatureOffset, SEEK_SET) != 0) {
        perror("fseek failed");
        fclose(file);
        exit(1);
    }

    unsigned char ret_instruction = 0xC3; // RET instruction in x86 assembly

    if (fwrite(&ret_instruction, sizeof(unsigned char), 1, file) != 1) {
        perror("fwrite failed");
        fclose(file);
        exit(1);
    }

    printf("Virus at offset %d neutralized.\n", signatureOffset);

    fclose(file);
}

void detect_signature_Offset(char *buffer, unsigned int size, link *virus_list){
    while(virus_list != NULL){
        int index = is_signature_in_buffer(buffer, size, virus_list->vir->sig,virus_list->vir->SigSize);
        if(index >= 0){
            neutralize_virus(suspected_file_name, index);
        }
        virus_list = virus_list->nextVirus;
    }
}


int main(int argc, char **argv) {
    if(argc > 1){
        suspected_file_name = argv[1];
        suspected_file = fopen(suspected_file_name, "rb");
        if (suspected_file == NULL) {
            perror("Failed to open suspected file");
            exit(1);
        }
        fseek(suspected_file, 0, SEEK_END);
        file_size = ftell(suspected_file);
        fseek(suspected_file, 0, SEEK_SET);
        copy_file_to_buffer();
    }

    char buffer[100];
    struct fun_desc menu[] = {
        { "Set signatures file name", SetSigFileName },
        { "Load signatures", LoadSignatures },
        { "Print signatures", PrintSignatures },
        { "Detect viruses", DetectViruses },
        { "Fix file", FixFile },
        { "Quit", Quit },
        { NULL, NULL }
    };

    while (true) {
        printf("Select operation from the following menu:\n");
        for (int i = 0; i < sizeof(menu) / sizeof(menu[0]) - 1; i++) {
            printf("%d) %s\n", i, menu[i].name);
        }

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }

        int input = atoi(buffer);
        if (input >= 0 && input < sizeof(menu) / sizeof(menu[0]) - 1) {
            menu[input].fun();
        } else {
            printf("Invalid option\n");
        }
    }

    Quit(); // Ensure resources are freed properly
    return 0;
}
