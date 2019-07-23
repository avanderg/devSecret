/* Names: Aaron VanderGraaff (avanderg)
 *        Denis Pyryev (dpyryev)
 * Assignment 4
 * May 24, 2019
 * CPE 453
 * Professor Nico
 *
 * Description: Device driver that will hold a secret message 
 * for a specific user, and can be read only with special
 * permissions. Once the device has been opened, the user
 * who opened it now owns the secret. The device can be opened
 * as many times as the user wants for reading, but only once
 * for writing. Once it is opened for writing and reading, the
 * message resets once all the read and write file descriptors 
 * are closed. Driver supports service update and will preserve
 * the secret data. Driver also is capable of passing permissions
 * to a different user that the original owner specifies with
 * a uid in the ioctl() function using the SSGRANT flag.
 *
 */

/* Libraries */
#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <sys/ioctl.h>

/* Constants */
#define WR 2 
#define RD 4 
#define SECRET_SIZE 8192 
#define TRUE 1
#define FALSE 0
#define NOT_SET 0

/* Struct of global things we save for service update */
struct save
{
    char secret_msg_s[SECRET_SIZE];
    int fd_count_s;
    int size_msg_s;
    uid_t owner_s;
    int owned_s;
    int open_read_s;
    int open_write_s;
    int transfer_flag_s;
};

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secret_geometry, (struct partition *entry) );
FORWARD _PROTOTYPE( int ssgrant_ioctl, (struct driver *d, message *m) );

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab =
{
    secret_name,
    secret_open,
    secret_close,
    ssgrant_ioctl,      /* Added this to support ioctl function */
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    secret_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/* Represents the /dev/secret device. */
PRIVATE struct device secret_device;

/* The secret message */
PRIVATE char secret_msg[SECRET_SIZE] = {'\0'}; 

/* Use fd_count to keep track of open file descriptors */
PRIVATE int fd_count = 0;

/* Size_msg keeps track of msg size */
PRIVATE int size_msg = 0;

/* Owner variable stores the owner of the secret, starts as unset */
PRIVATE uid_t owner = NOT_SET;

/* Open_write and open_read are flags to indicate whether a secret
   has been open for writing or reading, respectively  */
PRIVATE int open_read = FALSE;
PRIVATE int open_write = FALSE;

/* Owned indicates if the secret has an owner */
PRIVATE int owned = FALSE;

/* Transfer_flag caps our write size at SECRET_SIZE
   secret_transfer will only write a max block of size SECRET_SIZE,
   so transfer_flag stops a second call to transfer, which would
   overflow our device
 */
PRIVATE int transfer_flag = FALSE;

/* Global for saving state */
struct save saved_state;

/* Ioctl function for transferring ownership of a secret */
PRIVATE int ssgrant_ioctl(d, m) 
    struct driver *d;
    message *m;
{
    struct ucred tmpcred;
    int res;

    /* If the ioctl is of type SSGRANT, transfer ownership */
    if (m->COUNT & SSGRANT)
    {
        /* New uid was passed in IO_GRANT, put that value into owner */
        res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT,
                0, (vir_bytes)&owner, sizeof(owner), D);
        return res;
    }
    /* If the ioctl was not SSGRANT, return ENOTTY */
    else
    {
        return ENOTTY;
    }
}

/* Do we need this? */
PRIVATE char * secret_name(void)
{
    return "secret";
}

/* Called in response to a open() system call */
PRIVATE int secret_open(d, m)
    struct driver *d;
    message *m;
{
    int res;
    struct ucred mycred;
    struct ucred tmpcred;
    uid_t tmp;

    /* If the user tries to open with read and write perms, fail */
    if (m->COUNT & RD && m->COUNT & WR)
    {
        return EACCES;
    }

    /* Do the write stuff */
    else if (m->COUNT & WR)
    {

        /* If the secret is empty (ie hasn't been opened for writing,
           assign the user that called the open as the owner, then set
           owned to TRUE and open_write to TRUE.
        */
        if (!owned && !open_write)
        {
            /* Obtain uid of calling user */
            res = getnucred(m->IO_ENDPT, &mycred);
            if (res == -1) {
                return errno;
            }
            owner = mycred.uid;
            owned = TRUE;
            open_write = TRUE;
            fd_count++; /* Open succeeded, increment fd_count */
            return OK;
        }
        
        /* If the file is owned but hasn't been opened for writing yet */
        else if (owned && !open_write) 
        {
            /* Obtain uid of calling user */
            res = getnucred(m->IO_ENDPT, &tmpcred);
            if (res == -1) 
            {
                return errno; 
            }
            tmp = tmpcred.uid;
            
            /* If the person trying to write is owner, ok */
            if (tmp == owner) 
            {
                fd_count++;
                open_write = TRUE;
                return OK;
            }
            /* Otherwise, permission denied */
            else 
            {
                return EACCES;
            }
        }

        /* We have problems, figure out which error to report */
        else 
        {
            /* Obtain the uid of calling user */
            res = getnucred(m->IO_ENDPT, &tmpcred);
            if (res == -1) 
            {
                return errno;
            }
            tmp = tmpcred.uid;

            /* If the owner tries to open again, report that the
               device is full. */
            if (owner == tmp) 
            {
                return ENOSPC;
            }
            
            /* If someone who isn't the owner tries to access the secret,
               report that they don't have permission to see it */
            else 
            {
                return EACCES;
            }
        }
    }

    /* Do the read stuff */
    else if (m->COUNT & RD) 
    {
        /* If the file isn't owned, assign this user as the owner */
        if (!owned) 
        {
            /* Obtain uid of calling user */
            res = getnucred(m->IO_ENDPT, &mycred);
            if (res == -1) 
            {
                return errno;
            }
            owner = mycred.uid;
            owned = TRUE;
            open_read = TRUE;
            fd_count++; /* Open succeeded, increment fd_count */
            return OK;
        }
        else 
        {
            /* Check who wants to read */
            res = getnucred(m->IO_ENDPT, &tmpcred);
            if (res == -1)
            {
                return errno; 
            }
            tmp = tmpcred.uid;
            
            /* If the person trying to read is owner, ok */
            if (tmp == owner)
            {
                fd_count++;
                /* Secret has been read */
                open_read = TRUE;
                return OK;
            }
            /* If the person trying to read is not the owner, 
               report error */
            else 
            {
                return EACCES;
            }
        }
    }
} 

/* Called through the use of a close system call */
PRIVATE int secret_close(d, m)
    struct driver *d;
    message *m;
{
    int i;
    
    fd_count--; /* We're closing, decrement fd counter */

    /* If there are no open file descriptors, the secret has been written,
       and the secret has been read, reset to the initial state */
    if (fd_count == 0 && open_read) {
        owned = FALSE;
        open_read = FALSE;
        transfer_flag = FALSE;
        open_write = FALSE;
        size_msg = 0;

        /* Clear the old secret */
        for (i=0; i<SECRET_SIZE; i++) {
           secret_msg[i] = '\0';
        } 
    }
        
    /* Always let the files close :) */
    return OK;
}

/* Do we need this? */
PRIVATE struct device * secret_prepare(dev)
    int dev;
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = SECRET_SIZE; 
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

/* Called when there is a write or read system call */
PRIVATE int secret_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    int bytes, ret, i, len;

    /* Checks for Write or Read opcode */
    switch (opcode)
    {
        /* READ */
        case DEV_GATHER_S:
           
            bytes = size_msg - position.lo< iov->iov_size ?
                    size_msg - position.lo: iov->iov_size;

            /* If there's nothing to read, return */
            if (bytes <= 0 || size_msg <= 0)
            {
                return OK;
            }
              
            /* Copy the secret message to iov */
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (secret_msg),
                                 size_msg, D); 
            iov->iov_size -= bytes; 
           
           break;

        /* WRITE */
        case DEV_SCATTER_S: 

            /* If the tranfer_flag is set, that means we ran this before
               and the file is bigger than the buffer we gave it 
               (size SECRET_SIZE). */
            if (transfer_flag)
            {
                return ENOSPC;
            }

            /* Set transfer_flag for next round */
            transfer_flag = TRUE;

            bytes = SECRET_SIZE - position.lo< iov->iov_size ?
                    SECRET_SIZE - position.lo: iov->iov_size;

            /* Copy iov information to secret_msg */
            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                    (vir_bytes) (secret_msg), iov->iov_size,
                    D); 

            /* Increment size_msg */
            size_msg += iov->iov_size;
            
            iov->iov_size -= bytes;
            break;

        default:
            return EINVAL;
    }
    return ret;
}

/* Do we need this? */
PRIVATE void secret_geometry(entry)
    struct partition *entry;
{
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

/* Sef functions */
PRIVATE int sef_cb_lu_state_save(int state) {
    /* Save the state. */

    /* Save all our globals into a saved struct */
    strcpy(saved_state.secret_msg_s, secret_msg);

    saved_state.fd_count_s = fd_count;
    saved_state.size_msg_s = size_msg;
    saved_state.owner_s = owner;
    saved_state.owned_s = owned;
    saved_state.open_read_s = open_read;
    saved_state.open_write_s = open_write;
    saved_state.transfer_flag_s = transfer_flag;

    /* Publish them */
    ds_publish_mem("save", &saved_state, sizeof(saved_state),
            DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
    /* Restore the state. */
    u32_t value;
    size_t my_size = sizeof(saved_state);

    /* Retrieve saved_state struct and reassign globals */
    ds_retrieve_mem("save",(char *)&saved_state, &my_size);
    
    /* Restore all globals */
    strcpy(secret_msg, saved_state.secret_msg_s); 
    fd_count = saved_state.fd_count_s;
    size_msg = saved_state.size_msg_s;
    owner = saved_state.owner_s;
    owned = saved_state.owned_s;
    open_read = saved_state.open_read_s; 
    open_write = saved_state.open_write_s;
    transfer_flag = saved_state.transfer_flag_s;
    
    ds_delete_mem("save");

    return OK;
}

PRIVATE void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;

    /* open_counter = 0; */
    switch(type) {
        case SEF_INIT_FRESH:
            /* printf("%s", SECRET_MESSAGE); */
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

        break;

        case SEF_INIT_RESTART:
            /*sef_cb_lu_state_save(SEF_INIT_RESTART); */
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}

