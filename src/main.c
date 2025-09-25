#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <libserialport.h>

typedef struct usb_recorder {
    struct sp_port *port;
    bool opened;
    FILE *file;
    unsigned int timeout;

    const char* port_name;
    const char* path;

    uint8_t* buf;
    unsigned long bufsize;

    int baudrate;
    int databits;
    int stopbits;
    enum sp_parity parity;

} usb_recorder;

void usb_recorder_free(usb_recorder* c) {
    if (c->port != NULL) {
        if (c->opened) {
            sp_close(c->port);
        }
        sp_free_port(c->port);
        c->port = NULL;
    }
    if (c->file != NULL) {
        fclose(c->file);
        c->file = NULL;
    }
    if (c->buf != NULL) {
        free(c->buf);
        c->buf = NULL;
    }
}

int parse_args(usb_recorder* c, int argc, char **argv) {

    c->bufsize = 4096;
    c->timeout = 1000;
    c->port_name = NULL;
    c->path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "t:n:b:d:s:p:")) != -1) {
        char* endptr;
        unsigned long value;
        const char* arg_name;
        switch (opt) {
        case 't':
        case 'n':
        case 'd':
        case 's':
        case 'b':
            value = strtoul(optarg, &endptr, 10);
            if (*endptr == 0) {
                switch (opt) {
                case 't': c->timeout = value; break;
                case 'n': c->bufsize = value; break;
                case 'd': c->databits = value; break;
                case 's': c->stopbits = value; break;
                case 'b': c->baudrate = value; break;
                }
            } else {
                switch (opt) {
                case 't': arg_name = "timeout"; break;
                case 'n': arg_name = "bufsize"; break;
                case 'd': arg_name = "databits"; break;
                case 's': arg_name = "stopbits"; break;
                case 'b': arg_name = "baudrate"; break;
                }
                fprintf(stderr, "Illegal %s argument: %s\n", arg_name, optarg);
                return -1;
            }
            break;

            value = strtoul(optarg, &endptr, 10);
            if (*endptr == 0) {
                c->bufsize = value;
            } else {
                fprintf(stderr, "Illegal bufsize argument: %s\n", optarg);
                return -1;
            }
            break;

        case 'p':
            switch (*optarg) {
            case 'N': c->parity = SP_PARITY_NONE; break;
            case 'E': c->parity = SP_PARITY_EVEN; break;
            case 'O': c->parity = SP_PARITY_ODD; break;
            case 'M': c->parity = SP_PARITY_MARK; break;
            case 'S': c->parity = SP_PARITY_SPACE; break;
            default:
                fprintf(stderr, "Illegal parity argument: %s\n", optarg);
                return -1;
            }
            break;
        }
    }

    if (argc - optind < 2) {
        fputs("Usage: usb_capture"
            " [-t <timeout>]"
            " [-n <bufsize>]"
            " [-b <baudrate>]"
            " [-d <databits>]"
            " [-p <parity: N|E|O|M|S>]"
            " [-s <stopbits>]"
            " <port>"
            " <file>"
            "\n", stderr);
        return -1;
    }

    c->port_name = argv[optind];
    c->path = argv[optind + 1];
    return 0;
}


/* Example of how to get a list of serial ports on the system.
 *
 * This example file is released to the public domain. */

/* Example of a helper function for error handling. */
int sp_err(enum sp_return result) {
    int error_code;
    char *error_message;

    switch (result) {
    case SP_ERR_ARG:
        /* When SP_ERR_ARG is returned, there was a problem with one
         * or more of the arguments passed to the function, e.g. a null
         * pointer or an invalid value. This generally implies a bug in
         * the calling code. */
        printf("Error: Invalid argument.\n");
        return 1;

    case SP_ERR_FAIL:
        /* When SP_ERR_FAIL is returned, there was an error from the OS,
         * which we can obtain the error code and message for. These
         * calls must be made in the same thread as the call that
         * returned SP_ERR_FAIL, and before any other system functions
         * are called in that thread, or they may not return the
         * correct results. */
        error_code = sp_last_error_code();
        error_message = sp_last_error_message();
        printf("Error: Failed: OS error code: %d, message: '%s'\n",
            error_code, error_message);
        /* The error message should be freed after use. */
        sp_free_error_message(error_message);
        return 2;

    case SP_ERR_SUPP:
        /* When SP_ERR_SUPP is returned, the function was asked to do
         * something that isn't supported by the current OS or device,
         * or that libserialport doesn't know how to do in the current
         * version. */
        printf("Error: Not supported.\n");
        return 3;

    case SP_ERR_MEM:
        /* When SP_ERR_MEM is returned, libserialport wasn't able to
         * allocate some memory it needed. Since the library doesn't
         * normally use any large data structures, this probably means
         * the system is critically low on memory and recovery will
         * require very careful handling. The library itself will
         * always try to handle any allocation failure safely.
         *
         * In this example, we'll just try to exit gracefully without
         * calling printf, which might need to allocate further memory. */
        return 4;

    case SP_OK:
    default:
        /* A return value of SP_OK, defined as zero, means that the
         * operation succeeded. */
         /* Some fuctions can also return a value greater than zero to
         * indicate a numeric result, such as the number of bytes read by
         * sp_blocking_read(). So when writing an error handling wrapper
         * function like this one, it's helpful to return the result so
         * that it can be used. */
        return 0;
    }
}

int init_port( usb_recorder* c ) {
    int code;
    if ((code = sp_err( sp_get_port_by_name(c->port_name, &c->port) )) != 0) { return code; }


    struct sp_port* port = c->port;
    if ((code = sp_err( sp_open(port, SP_MODE_READ) )) != 0) { return code; }
    c->opened = true;

    if ((code = sp_err( sp_set_baudrate(port, c->baudrate) )) != 0) { return code; }
    if ((code = sp_err( sp_set_bits(port, c->databits) )) != 0) { return code; }
    if ((code = sp_err( sp_set_parity(port, c->parity) )) != 0) { return code; }
    if ((code = sp_err( sp_set_stopbits(port, c->stopbits) )) != 0) { return code; }
    if ((code = sp_err( sp_set_flowcontrol(port, SP_FLOWCONTROL_NONE) )) != 0) { return code; }
    return 0;
}

int main(int argc, char **argv) {
    usb_recorder c = {0};
    
    int exit_code;
    if ((exit_code = parse_args(&c, argc, argv)) != 0) {
        return exit_code;
    }

    if ((exit_code = init_port(&c)) != 0) {
        return exit_code;
    }

    uint8_t* data = malloc(c.bufsize);
    if (data == NULL) {
        fprintf(stderr, "Can't allocate buffer for reading data");
        usb_recorder_free(&c);
        return -1;
    }

    c.file = fopen(c.path, "wb");
    if (c.file == NULL) {
        fprintf(stderr, "Can't open file for writing: %s; Error: %s", c.path, strerror(errno));
        usb_recorder_free(&c);
        return -1;
    }

    exit_code = sp_err( sp_flush(c.port, SP_BUF_INPUT) );
    while (exit_code == 0) {
        enum sp_return ret = sp_blocking_read(c.port, data, c.bufsize, c.timeout);
        if (ret < 0) {
            exit_code = sp_err(ret);
            break;
        }
        size_t r_bytes = (size_t) ret;
        size_t w_bytes = fwrite(data, 1, r_bytes, c.file);
        printf("%zu bytes was read, %zu bytes written\n", r_bytes, w_bytes);
        if (w_bytes != r_bytes) {
            fprintf(stderr, "Can't write data to file: %s; Error: %s", c.path, strerror(errno));
            break;
        }
    }

    usb_recorder_free(&c);
    return 0;
}
