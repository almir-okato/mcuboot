/*
 * SPDX-FileCopyrightText: 2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <bootutil/bootutil.h>
#include <bootutil/bootutil_log.h>
#include <bootutil/fault_injection_hardening.h>
#include <bootutil/image.h>

#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_random.h"
#include "bootloader_soc.h"

#include "esp_assert.h"

#ifdef CONFIG_MCUBOOT_SERIAL
#include "boot_serial/boot_serial.h"
#include "serial_adapter/serial_adapter.h"

const struct boot_uart_funcs boot_funcs = {
    .read = console_read,
    .write = console_write
};
#endif

#if defined(CONFIG_EFUSE_VIRTUAL_KEEP_IN_FLASH) || defined(CONFIG_SECURE_BOOT)
#include "esp_efuse.h"
#endif
#ifdef CONFIG_SECURE_BOOT
#include "esp_secure_boot.h"
#endif
#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED
#include "esp_flash_encrypt.h"
#endif

#include "esp_loader.h"
#include "os/os_malloc.h"

#define IMAGE_INDEX_0   0
#define IMAGE_INDEX_1   1

#define PRIMARY_SLOT    0
#define SECONDARY_SLOT  1

#ifdef CONFIG_SECURE_BOOT
extern esp_err_t check_and_generate_secure_boot_keys(void);
#endif

void do_boot(struct boot_rsp *rsp)
{
    BOOT_LOG_INF("br_image_off = 0x%x", rsp->br_image_off);
    BOOT_LOG_INF("ih_hdr_size = 0x%x", rsp->br_hdr->ih_hdr_size);
    int slot = (rsp->br_image_off == CONFIG_ESP_IMAGE0_PRIMARY_START_ADDRESS) ? PRIMARY_SLOT : SECONDARY_SLOT;
    start_cpu0_image(IMAGE_INDEX_0, slot, rsp->br_hdr->ih_hdr_size);
}

#ifdef CONFIG_ESP_MULTI_PROCESSOR_BOOT
int read_image_header(uint32_t img_index, uint32_t slot, struct image_header *img_header)
{
    const struct flash_area *fap;
    int area_id;
    int rc = 0;

    area_id = flash_area_id_from_multi_image_slot(img_index, slot);
    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    if (flash_area_read(fap, 0, img_header, sizeof(struct image_header))) {
        rc = BOOT_EFLASH;
        goto done;
    }

    BOOT_LOG_INF("Image offset = 0x%x", fap->fa_off);
    BOOT_LOG_INF("Image header size = 0x%x", img_header->ih_hdr_size);

done:
    flash_area_close(fap);
    return rc;
}

void do_boot_appcpu(uint32_t img_index, uint32_t slot)
{
    struct image_header img_header;

    if (read_image_header(img_index, slot, &img_header) != 0) {
        FIH_PANIC;
    }

    start_cpu1_image(img_index, slot, img_header.ih_hdr_size);
}
#endif

#include "bootutil/bootutil_public.h"
#include "bootutil_priv.h"
#include "bootutil_misc.h"

const union boot_img_magic_t testmagic1 = {
    .val = {
        0x77, 0xc2, 0x95, 0xf3,
        0x60, 0xd2, 0xef, 0x7f,
        0x35, 0x52, 0x50, 0x0f,
        0x2c, 0xb6, 0x79, 0x80
    }
};
const union boot_img_magic_t testmagic2 = {
    .val = {
        0x20, 0x00, 0x2d, 0xe1,
        0x5d, 0x29, 0x41, 0x0b,
        0x8d, 0x77, 0x67, 0x9c,
        0x11, 0x0f, 0x1f, 0x8a
    }
};

#define TESTMAGIC1 testmagic1.val
#define TESTMAGIC2 testmagic2.val

int
write_test(struct flash_area *fap)
{
    int rc;
    uint8_t magic[BOOT_MAGIC_ALIGN_SIZE];
    uint8_t erased_val;

    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;
    uint32_t test_off = swap_size_off - 0x200;

    uint32_t off = test_off;
    erased_val = flash_area_erased_val(fap);

    BOOT_LOG_INF("----------WRITING----------");
    BOOT_LOG_INF("WRITING random data: fa_id=%d off=0x%lx (0x%lx)",
                flash_area_get_id(fap), (unsigned long)off,
                (unsigned long)(flash_area_get_off(fap) + off));

    while (off < swap_size_off) {
        uint8_t index_random = off % BOOT_MAGIC_ALIGN_SIZE*2 == 0 ? 0 : BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ;
        uint8_t index_erased = off % BOOT_MAGIC_ALIGN_SIZE*2 == 0 ? BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ : 0;
        bootloader_fill_random(&magic[index_random], BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ);
        memset(&magic[index_erased], erased_val, BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ);

        for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                magic[i], magic[i+1], magic[i+2], magic[i+3]);
        }

        rc = flash_area_erase(fap, off, BOOT_MAGIC_ALIGN_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        rc = flash_area_write(fap, off, &magic[0], BOOT_MAGIC_ALIGN_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        off += BOOT_MAGIC_ALIGN_SIZE;
    }
    BOOT_LOG_INF("----------WRITING----------");

    return 0;
}

int
read_test(struct flash_area *fap)
{
    int rc;
    uint8_t read_buf[BOOT_MAGIC_ALIGN_SIZE * 4];
    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;
    uint32_t test_off = swap_size_off - 0x200;
    uint32_t off = test_off;

    BOOT_LOG_INF("----------READING----------");
    BOOT_LOG_INF("READING data written before: fa_id=%d off=0x%lx (0x%lx)",
            flash_area_get_id(fap), (unsigned long)off,
            (unsigned long)(flash_area_get_off(fap) + off));

    while (off < swap_size_off) {
        rc = flash_area_read(fap,off, read_buf, BOOT_MAGIC_ALIGN_SIZE * 4);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE * 4; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
        }
        off += BOOT_MAGIC_ALIGN_SIZE * 4;
    }
    BOOT_LOG_INF("----------READING----------");
    return 0;
}

int
write_noerase_test(struct flash_area *fap)
{
    int rc;
    uint8_t magic[BOOT_MAGIC_ALIGN_SIZE];
    uint8_t erased_val;

    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;

    uint32_t off = swap_size_off;

    BOOT_LOG_INF("----------WRITING-WITHOUT-ERASE----------");
    BOOT_LOG_INF("WRITING-WITHOUT-ERASE random data + TESTMAGIC1, TESTMAGIC2 + erased_val : fa_id=%d off=0x%lx (0x%lx)",
                flash_area_get_id(fap), (unsigned long)off,
                (unsigned long)(flash_area_get_off(fap) + off));

    bootloader_fill_random(&magic[0], BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ);
    memcpy(&magic[BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ], TESTMAGIC1, BOOT_MAGIC_SZ);

    for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            magic[i], magic[i+1], magic[i+2], magic[i+3]);
    }

    rc = flash_area_write(fap, off, &magic[0], BOOT_MAGIC_ALIGN_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += BOOT_MAGIC_ALIGN_SIZE;

    erased_val = flash_area_erased_val(fap);

    memset(&magic[BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ], erased_val, BOOT_MAGIC_ALIGN_SIZE - BOOT_MAGIC_SZ);
    memcpy(&magic[0], TESTMAGIC2, BOOT_MAGIC_SZ);

    for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            magic[i], magic[i+1], magic[i+2], magic[i+3]);
    }

    rc = flash_area_write(fap, off, &magic[0], BOOT_MAGIC_ALIGN_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    BOOT_LOG_INF("----------WRITING-WITHOUT-ERASE----------");

    return 0;
}

int
read_noerase_test(struct flash_area *fap)
{
    int rc;
    uint8_t read_buf[BOOT_MAGIC_ALIGN_SIZE];
    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;
    uint32_t off = swap_size_off;

    BOOT_LOG_INF("----------READING-WITHOUT-ERASE----------");
    BOOT_LOG_INF("READING-WITHOUT-ERASE data written: fa_id=%d off=0x%lx (0x%lx)",
            flash_area_get_id(fap), (unsigned long)off,
            (unsigned long)(flash_area_get_off(fap) + off));

    while (off < (swap_size_off + (BOOT_MAGIC_ALIGN_SIZE * 2))) {
        rc = flash_area_read(fap,off, read_buf, BOOT_MAGIC_ALIGN_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
        }
        off = off + BOOT_MAGIC_ALIGN_SIZE;
    }

    BOOT_LOG_INF("----------READING-WITHOUT-ERASE----------");

    return 0;
}

#define UNALIGN_OFF 16
int
write_unaligned_test(struct flash_area *fap)
{
    int rc;
    uint8_t magic[BOOT_MAGIC_ALIGN_SIZE];
    uint8_t read_buf[BOOT_MAGIC_ALIGN_SIZE];

    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;

    uint32_t off = swap_size_off + (BOOT_MAGIC_ALIGN_SIZE * 2);
    uint32_t off_unaligned = off + UNALIGN_OFF;

    BOOT_LOG_INF("----------WRITING-UNALIGNED----------");
    BOOT_LOG_INF("WRITING-UNALIGNED: fa_id=%d off=0x%lx (0x%lx) - whats EXPECTED:",
                flash_area_get_id(fap), (unsigned long)off,
                (unsigned long)(flash_area_get_off(fap) + off));

    rc = flash_area_read(fap,off, read_buf, BOOT_MAGIC_ALIGN_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    memcpy(&read_buf[UNALIGN_OFF], TESTMAGIC1, BOOT_MAGIC_SZ);

    for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    memcpy(&magic[0], TESTMAGIC1, BOOT_MAGIC_SZ);

    // rc = flash_area_erase(fap, off_unaligned, BOOT_MAGIC_SZ);
    // if (rc != 0) {
    //     return BOOT_EFLASH;
    // }
    rc = flash_area_erase(fap, off, BOOT_MAGIC_ALIGN_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    rc = flash_area_write(fap, off_unaligned, &magic[0], BOOT_MAGIC_SZ);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    BOOT_LOG_INF("----------WRITING-UNALIGNED----------");

    return 0;
}

int
read_unaligned_test(struct flash_area *fap)
{
    int rc;
    uint8_t read_buf[BOOT_MAGIC_ALIGN_SIZE];
    uint32_t swap_size_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;
    uint32_t off = swap_size_off + (BOOT_MAGIC_ALIGN_SIZE * 2);

    BOOT_LOG_INF("----------READING-UNALIGNED----------");
    BOOT_LOG_INF("READING-UNALIGNED data written: fa_id=%d off=0x%lx (0x%lx)",
            flash_area_get_id(fap), (unsigned long)off,
            (unsigned long)(flash_area_get_off(fap) + off));

    while (off < swap_size_off + (BOOT_MAGIC_ALIGN_SIZE * 2) + BOOT_MAGIC_ALIGN_SIZE) {
        rc = flash_area_read(fap,off, read_buf, BOOT_MAGIC_ALIGN_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint8_t i=0; i<BOOT_MAGIC_ALIGN_SIZE; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
        }
        off += BOOT_MAGIC_ALIGN_SIZE;
    }

    BOOT_LOG_INF("----------READING-UNALIGNED----------");

    return 0;
}

int
write_read_trailer_test() {
    int rc;
    int fa_id;
    uint8_t read_buf[BOOT_MAX_ALIGN * 5];
    const struct flash_area *fap;

    BOOT_LOG_INF("----------WRITE-READ-TRAILER----------");

    for (uint8_t slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        fa_id = flash_area_id_from_multi_image_slot(0, slot);
        rc = flash_area_open(fa_id, &fap);

        rc = boot_write_swap_info(fap, 0xA, 0x5);
        assert(rc == 0);

        rc = boot_write_image_ok(fap);
        assert(rc == 0);

        rc = boot_write_swap_size(fap, 0xA6152268);
        assert(rc == 0);

        rc = boot_write_magic(fap);
        assert(rc == 0);

        rc = boot_write_copy_done(fap);
        assert(rc == 0);
    }
    fa_id = FLASH_AREA_IMAGE_SCRATCH;
    rc = flash_area_open(fa_id, &fap);
    rc = boot_write_swap_info(fap, 0xA, 0x5);
    assert(rc == 0);
    rc = boot_write_image_ok(fap);
    assert(rc == 0);
    rc = boot_write_swap_size(fap, 0xA6152268);
    assert(rc == 0);
    rc = boot_write_magic(fap);
    assert(rc == 0);
    rc = boot_write_copy_done(fap);
    assert(rc == 0);

    uint32_t swap_status_off;
    uint32_t swap_info_off;
    for (uint8_t slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        fa_id = flash_area_id_from_multi_image_slot(0, slot);
        rc = flash_area_open(fa_id, &fap);
        swap_status_off = boot_status_off(fap);
        swap_info_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;

        BOOT_LOG_INF("DEBUG fa_id=%d (0x%lx) swap_status_off=0x%lx trailer size=%d (0x%x)",
            fa_id, fap->fa_off, fap->fa_off+swap_status_off,
            fap->fa_size - swap_status_off, fap->fa_size - swap_status_off);

        rc = flash_area_read(fap,swap_info_off, read_buf, BOOT_MAX_ALIGN * 5);
        BOOT_LOG_INF("DEBUG swap_size_off=0x%lx whats read  rc=0x%x", fap->fa_off+swap_info_off, rc);
        for (uint8_t i=0; i<BOOT_MAX_ALIGN * 5; i=i+4) {
            if (i % BOOT_MAX_ALIGN == 0) {
                BOOT_LOG_INF(" ");
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
        }
    }
    fa_id = FLASH_AREA_IMAGE_SCRATCH;
    rc = flash_area_open(fa_id, &fap);
    swap_status_off = boot_status_off(fap);
    swap_info_off = boot_swap_info_off(fap) - BOOT_MAX_ALIGN;
    BOOT_LOG_INF("DEBUG fa_id=%d (0x%lx) SCRATCH swap_status_off=0x%lx trailer size=%d (0x%x)",
        fa_id, fap->fa_off, fap->fa_off+swap_status_off,
        fap->fa_size - swap_status_off, fap->fa_size - swap_status_off);

    rc = flash_area_read(fap,swap_info_off, read_buf, BOOT_MAX_ALIGN * 5);
    BOOT_LOG_INF("DEBUG swap_size_off=0x%lx whats read  rc=0x%x", fap->fa_off+swap_info_off, rc);
    for (uint8_t i=0; i<BOOT_MAX_ALIGN * 5; i=i+4) {
        if (i % BOOT_MAX_ALIGN == 0) {
            BOOT_LOG_INF(" ");
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    BOOT_LOG_INF("----------WRITE-READ-TRAILER----------");
    return rc;
}


#define FLASH_SECTOR_SIZE 0x1000
int flash_area_read_unencrypted(const struct flash_area *fa, uint32_t off, void *dst,
                                uint32_t len);

int
erased_val_test(struct flash_area *fap)
{
    int rc;

    uint32_t off = 0x12000;
    BOOT_LOG_INF("----------ERASE-VAL-TEST----------");

    rc = flash_area_erase(fap, off, FLASH_SECTOR_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    uint8_t read_buf[FLASH_SECTOR_SIZE];

    BOOT_LOG_INF("READING SECTOR SIZE bytes");

    rc = flash_area_read(fap,off, read_buf, FLASH_SECTOR_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    BOOT_LOG_INF("READING SECTOR SIZE bytes - UNENCRYPTED");

    rc = flash_area_read_unencrypted(fap, off, read_buf, FLASH_SECTOR_SIZE);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    BOOT_LOG_INF("READING EACH 32 bytes");

    uint8_t read_buf2[32];
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE; i=i+32) {
        rc = flash_area_read(fap,off + i, read_buf2, 32);
        if (rc != 0) {
            return BOOT_EFLASH;
        }

        BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        for (uint32_t j=0; j<32; j=j+4) {
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf2[j], read_buf2[j+1], read_buf2[j+2], read_buf2[j+3]);
        }

    }

    BOOT_LOG_INF("----------ERASE-VAL-TEST----------");

    return 0;
}

#define FLASH_SECTOR_SIZE_N (FLASH_SECTOR_SIZE * 3)

int
erased_val_2_test(struct flash_area *fap)
{
    int rc;

    uint32_t off = 0x13000;
    uint8_t read_buf[FLASH_SECTOR_SIZE_N];

    BOOT_LOG_INF("----------ERASE-VAL-TEST-2----------");

    rc = flash_area_erase(fap, off, FLASH_SECTOR_SIZE_N);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    BOOT_LOG_INF("READING N SECTOR SIZE bytes");

    rc = flash_area_read(fap,off, read_buf, FLASH_SECTOR_SIZE_N);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE_N; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    BOOT_LOG_INF("READING N SECTOR SIZE bytes - UNENCRYPTED");

    rc = flash_area_read_unencrypted(fap, off, read_buf, FLASH_SECTOR_SIZE_N);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE_N; i=i+4) {
        if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
            BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        }
        BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
            read_buf[i], read_buf[i+1], read_buf[i+2], read_buf[i+3]);
    }

    BOOT_LOG_INF("READING EACH 32 bytes");

    uint8_t read_buf2[32];
    for (uint32_t i=0; i<FLASH_SECTOR_SIZE_N; i=i+32) {
        rc = flash_area_read(fap,off + i, read_buf2, 32);
        if (rc != 0) {
            return BOOT_EFLASH;
        }

        BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + i));
        for (uint32_t j=0; j<32; j=j+4) {
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf2[j], read_buf2[j+1], read_buf2[j+2], read_buf2[j+3]);
        }

    }

    BOOT_LOG_INF("----------ERASE-VAL-TEST-2----------");

    return 0;
}

static uint8_t reset_buf_pattern[FLASH_SECTOR_SIZE_N] = {0};
static uint8_t read_buf_sec[FLASH_SECTOR_SIZE] = {0};

int
erase_tests_reset_area(struct flash_area *fap, uint32_t off, size_t len)
{
    int rc;
    BOOT_LOG_INF("--RESETING-AREA--");
    rc = flash_area_erase(fap, off, len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    if (reset_buf_pattern[0] == 0) {
        memset(&reset_buf_pattern[0], 0xA5, FLASH_SECTOR_SIZE_N);
    }

    memset(&read_buf_sec[0], 0, FLASH_SECTOR_SIZE);

    rc = flash_area_write(fap, off, &reset_buf_pattern[0], len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    BOOT_LOG_INF("--RESETING-AREA--");
    return 0;
}

int
erase_tests_read_area(struct flash_area *fap, uint32_t off, size_t len)
{
    int rc;

    BOOT_LOG_INF(">>READING SECTOR SIZE bytes>>");
    for (size_t read_len = 0; read_len < len; read_len += FLASH_SECTOR_SIZE) {
        rc = flash_area_read(fap,off + read_len, read_buf_sec, FLASH_SECTOR_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint32_t i=0; i<FLASH_SECTOR_SIZE; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + read_len + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf_sec[i], read_buf_sec[i+1], read_buf_sec[i+2], read_buf_sec[i+3]);
        }
    }
    BOOT_LOG_INF("<<READING SECTOR SIZE bytes<<");

    BOOT_LOG_INF(">>READING SECTOR SIZE bytes - UNENCRYPTED>>");
    for (size_t read_len = 0; read_len < len; read_len += FLASH_SECTOR_SIZE) {
        rc = flash_area_read_unencrypted(fap, off + read_len, read_buf_sec, FLASH_SECTOR_SIZE);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint32_t i=0; i<FLASH_SECTOR_SIZE; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + read_len + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf_sec[i], read_buf_sec[i+1], read_buf_sec[i+2], read_buf_sec[i+3]);
        }
    }
    BOOT_LOG_INF("<<READING SECTOR SIZE bytes - UNENCRYPTED<<");

    return 0;
}

int
erase_tests(struct flash_area *fap)
{
    int rc;

    uint32_t off = 0x15000;
    uint32_t area_size;
    uint32_t area_start;
    uint32_t area_end;
    uint32_t head_size;
    uint32_t tail_off;
    uint32_t tail_size;
    uint32_t erase_off;
    size_t size;
    BOOT_LOG_INF("----------ERASE-TESTS----------");


    // BOOT_LOG_INF("--CASE-ALL--");
    // area_size = FLASH_SECTOR_SIZE_N;
    // area_start = flash_area_get_off(fap) + off;
    // area_end = area_start + area_size;
    // head_size = 0;
    // tail_size = 0;
    // tail_off = area_size - tail_size;
    // size = area_size - tail_size - head_size;
    // erase_off = head_size;
    // BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
    //             area_start, head_size > 0 ? '|' : ' ',
    //             area_start + erase_off, area_start + erase_off + size,
    //             tail_size > 0 ? '|' : ' ', area_end, size);

    // rc = erase_tests_reset_area(fap, off, area_size);
    // if (rc != 0) {
    //     return BOOT_EFLASH;
    // }
    // rc = flash_area_erase(fap, off + erase_off, size);
    // if (rc != 0) {
    //     return BOOT_EFLASH;
    // }
    // rc = erase_tests_read_area(fap, off, area_size);
    // if (rc != 0) {
    //     return BOOT_EFLASH;
    // }
    // off += area_size;

    BOOT_LOG_INF("--CASE1-PRESERVE-TAIL--");
    area_size = FLASH_SECTOR_SIZE;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0;
    tail_size = 0xC00;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;

    BOOT_LOG_INF("--CASE2-PRESERVE-HEAD--");
    area_size = FLASH_SECTOR_SIZE;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0x400;
    tail_size = 0;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;

    BOOT_LOG_INF("--CASE3-PRESERVE-HEAD-PRESERVE-TAIL--");
    area_size = FLASH_SECTOR_SIZE;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0xA00;
    tail_size = 0x400;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;

    BOOT_LOG_INF("--CASE4-WHOLESEC-PRESERVE-TAIL--");
    area_size = FLASH_SECTOR_SIZE_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0;
    tail_size = 0xC00;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;

    BOOT_LOG_INF("--CASE5-PRESERVE-HEAD-WHOLESEC--");
    area_size = FLASH_SECTOR_SIZE_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0x400;
    tail_size = 0;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;

    BOOT_LOG_INF("--CASE6-PRESERVE-HEAD-WHOLESEC-PRESERVE-TAIL--");
    area_size = FLASH_SECTOR_SIZE_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    head_size = 0x400;
    tail_size = 0xC00;
    tail_off = area_size - tail_size;
    size = area_size - tail_size - head_size;
    erase_off = head_size;
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + erase_off, area_start + erase_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);
    rc = erase_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_erase(fap, off + erase_off, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = erase_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += area_size;


    BOOT_LOG_INF("----------ERASE-TESTS----------");

    return 0;
}

#define UNALIGN_OFFSET 16
#define FLASH_ALIGNMENT 32
#define WRITE_TEST_AREA_N FLASH_ALIGNMENT * 3
static uint8_t write_buf_pattern[WRITE_TEST_AREA_N] = {0};

int
write_tests_reset_area(struct flash_area *fap, uint32_t off, size_t len)
{
    int rc;
    BOOT_LOG_INF("--RESETING-AREA--");
    rc = flash_area_erase(fap, off, len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    if (write_buf_pattern[0] == 0) {
        memset(&write_buf_pattern[0], 0x43, WRITE_TEST_AREA_N);
    }

    memset(&read_buf_sec[0], 0, FLASH_SECTOR_SIZE);

    // rc = flash_area_write(fap, off, &reset_buf_pattern[0], len);
    // if (rc != 0) {
    //     return BOOT_EFLASH;
    // }
    BOOT_LOG_INF("--RESETING-AREA--");
    return 0;
}

int
write_tests_read_area(struct flash_area *fap, uint32_t off, size_t len)
{
    int rc;

    BOOT_LOG_INF(">>READING ALIGNMENT SIZE bytes>>");
    for (size_t read_len = 0; read_len < len; read_len += FLASH_ALIGNMENT) {
        rc = flash_area_read(fap,off + read_len, read_buf_sec, FLASH_ALIGNMENT);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint32_t i=0; i<FLASH_ALIGNMENT; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + read_len + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf_sec[i], read_buf_sec[i+1], read_buf_sec[i+2], read_buf_sec[i+3]);
        }
    }
    BOOT_LOG_INF("<<READING ALIGNMENT SIZE bytes<<");

    BOOT_LOG_INF(">>READING ALIGNMENT SIZE bytes - UNENCRYPTED>>");
    for (size_t read_len = 0; read_len < len; read_len += FLASH_ALIGNMENT) {
        rc = flash_area_read_unencrypted(fap, off + read_len, read_buf_sec, FLASH_ALIGNMENT);
        if (rc != 0) {
            return BOOT_EFLASH;
        }
        for (uint32_t i=0; i<FLASH_ALIGNMENT; i=i+4) {
            if (i % BOOT_MAGIC_ALIGN_SIZE == 0) {
                BOOT_LOG_INF("addr: 0x%08lx", (unsigned long)(flash_area_get_off(fap) + off + read_len + i));
            }
            BOOT_LOG_INF("0x%x 0x%x 0x%x 0x%x",
                read_buf_sec[i], read_buf_sec[i+1], read_buf_sec[i+2], read_buf_sec[i+3]);
        }
    }
    BOOT_LOG_INF("<<READING ALIGNMENT SIZE bytes - UNENCRYPTED<<");

    return 0;
}

int
write_tests(struct flash_area *fap)
{
    int rc;

    uint32_t off = 0x25000;
    uint32_t area_size;
    uint32_t area_start;
    uint32_t area_end;
    uint32_t head_size;
    uint32_t tail_off;
    uint32_t tail_size;
    uint32_t write_off;
    size_t size;
    BOOT_LOG_INF("----------WRITE-TESTS----------");

    BOOT_LOG_INF("--CASE-ALL--");
    area_size = WRITE_TEST_AREA_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0;
    size = WRITE_TEST_AREA_N;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE1-WRITE-HEAD--");
    area_size = FLASH_ALIGNMENT;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0;
    size = 0x10;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE2-WRITE-TAIL--");
    area_size = FLASH_ALIGNMENT;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0x14;
    size = 0x0C;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE3-WRITE-MIDDLE--");
    area_size = FLASH_ALIGNMENT;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0x0C;
    size = 0x0C;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE4-WRITE-BLOCK-WRITE-HEAD--");
    area_size = WRITE_TEST_AREA_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0;
    size = 0x28;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE5-WRITE-TAIL-WRITE-BLOCK--");
    area_size = WRITE_TEST_AREA_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0x14;
    size = 0x2C;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("--CASE6-WRITE-TAIL-WRITE-BLOCK-WRITE-HEAD--");
    area_size = WRITE_TEST_AREA_N;
    area_start = flash_area_get_off(fap) + off;
    area_end = area_start + area_size;
    write_off = 0x14;
    size = 0x34;
    head_size = write_off;
    tail_size = area_end - (area_start + write_off + size);
    BOOT_LOG_INF("-- area_start=0x%08x %c off=0x%08x off+size=0x%08x %c area_end=0x%08x size=0x%08x--",
                area_start, head_size > 0 ? '|' : ' ',
                area_start + write_off, area_start + write_off + size,
                tail_size > 0 ? '|' : ' ', area_end, size);

    rc = write_tests_reset_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = flash_area_write(fap, off + write_off, write_buf_pattern, size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    rc = write_tests_read_area(fap, off, area_size);
    if (rc != 0) {
        return BOOT_EFLASH;
    }
    off += FLASH_SECTOR_SIZE;

    BOOT_LOG_INF("----------WRITE-TESTS----------");

    return 0;
}

int main()
{
    if (bootloader_init() != ESP_OK) {
        FIH_PANIC;
    }

    /* Rough steps for a first boot when Secure Boot and/or Flash Encryption are still disabled on device:
     * Secure Boot:
     *   1) Calculate the SHA-256 hash digest of the public key and write to EFUSE.
     *   2) Validate the application images and prepare the booting process.
     *   3) Burn EFUSE to enable Secure Boot V2 (ABS_DONE_0).
     * Flash Encryption:
     *   4) Generate Flash Encryption key and write to EFUSE.
     *   5) Encrypt flash in-place including bootloader, image primary/secondary slot and scratch.
     *   6) Burn EFUSE to enable Flash Encryption.
     *   7) Reset system to ensure Flash Encryption cache resets properly.
     */

#ifdef CONFIG_EFUSE_VIRTUAL_KEEP_IN_FLASH
    BOOT_LOG_WRN("eFuse virtual mode is enabled. If Secure boot or Flash encryption is enabled then it does not provide any security. FOR TESTING ONLY!");
    esp_efuse_init_virtual_mode_in_flash(CONFIG_EFUSE_VIRTUAL_OFFSET, CONFIG_EFUSE_VIRTUAL_SIZE);
#endif

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED)
    esp_err_t err;
#endif

#ifdef CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER
    if (esp_secure_boot_enabled() ^ esp_flash_encrypt_initialized_once()) {
        BOOT_LOG_ERR("Secure Boot and Flash Encryption cannot be enabled separately, only together (their keys go into one eFuse key block)");
        FIH_PANIC;
    }

    if (!esp_secure_boot_enabled() || !esp_flash_encryption_enabled()) {
        esp_efuse_batch_write_begin();
    }
#endif // CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER

#ifdef CONFIG_SECURE_BOOT
    /* Steps 1 (see above for full description):
     *   1) Compute digest of the public key.
     */

    BOOT_LOG_INF("enabling secure boot v2...");

    bool sb_hw_enabled = esp_secure_boot_enabled();

    if (sb_hw_enabled) {
        BOOT_LOG_INF("secure boot v2 is already enabled, continuing..");
    } else {
        esp_efuse_batch_write_begin(); /* Batch all efuse writes at the end of this function */

        err = check_and_generate_secure_boot_keys();
        if (err != ESP_OK) {
            esp_efuse_batch_write_cancel();
            FIH_PANIC;
        }
    }
#endif

    os_heap_init();

    struct boot_rsp rsp;

    FIH_DECLARE(fih_rc, FIH_FAILURE);

#ifdef CONFIG_MCUBOOT_SERIAL
    boot_console_init();
    if (boot_serial_detect_pin()) {
        BOOT_LOG_INF("Enter the serial recovery mode");
        boot_serial_start(&boot_funcs);
    }
#endif

    uint32_t swap_status_off;
    uint32_t swap_info_off;
    const struct flash_area *fap;
    int fa_id;
    int rc;
    for (uint8_t slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        fa_id = flash_area_id_from_multi_image_slot(0, slot);
        rc = flash_area_open(fa_id, &fap);

        BOOT_LOG_INF("\nTESTS DEBUG fa_id=%d (0x%lx)", fa_id, fap->fa_off);

        // rc = erased_val_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = erased_val_2_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }

        // rc = write_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = read_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = write_noerase_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = read_noerase_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = write_unaligned_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }
        // rc = read_unaligned_test(fap);
        // if (rc != 0) {
        //     BOOT_LOG_INF("ERROR!");
        // }

    }
    fa_id = flash_area_id_from_multi_image_slot(0, 0);
    rc = flash_area_open(fa_id, &fap);
    rc = erase_tests(fap);
    if (rc != 0) {
            BOOT_LOG_INF("ERROR!");
    }
    rc = write_tests(fap);
    if (rc != 0) {
            BOOT_LOG_INF("ERROR!");
    }

    // write_read_trailer_test();
    while(1);


    /* Step 2 (see above for full description):
     *   2) MCUboot validates the application images and prepares the booting process.
     */

    /* MCUboot's boot_go validates and checks all images for update and returns
     * the load information for booting the main image
     */
    FIH_CALL(boot_go, fih_rc, &rsp);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        BOOT_LOG_ERR("Unable to find bootable image");
#ifdef CONFIG_SECURE_BOOT
        esp_efuse_batch_write_cancel();
#endif
        FIH_PANIC;
    }

#ifdef CONFIG_SECURE_BOOT
    /* Step 3 (see above for full description):
     *   3) Burn EFUSE to enable Secure Boot V2.
     */

    if (!sb_hw_enabled) {
        BOOT_LOG_INF("blowing secure boot efuse...");
        err = esp_secure_boot_enable_secure_features();
        if (err != ESP_OK) {
            esp_efuse_batch_write_cancel();
            FIH_PANIC;
        }

        err = esp_efuse_batch_write_commit();
        if (err != ESP_OK) {
            BOOT_LOG_ERR("Error programming security eFuses (err=0x%x).", err);
            FIH_PANIC;
        }

#ifdef CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE
        assert(esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE));
#endif

#ifndef CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER
        assert(esp_secure_boot_enabled());
        BOOT_LOG_INF("Secure boot permanently enabled");
#endif
    }
#endif

#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED
    /* Step 4, 5 & 6 (see above for full description):
     *   4) Generate Flash Encryption key and write to EFUSE.
     *   5) Encrypt flash in-place including bootloader, image primary/secondary slot and scratch.
     *   6) Burn EFUSE to enable flash encryption
     */
    BOOT_LOG_INF("Checking flash encryption...");
    bool flash_encryption_enabled = esp_flash_encrypt_state();
    if (!flash_encryption_enabled) {
#ifdef CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED
        BOOT_LOG_ERR("flash encryption is not enabled, and SECURE_FLASH_REQUIRE_ALREADY_ENABLED is set, refusing to boot.");
        FIH_PANIC;
#endif // CONFIG_SECURE_FLASH_REQUIRE_ALREADY_ENABLED

        if (esp_flash_encrypt_is_write_protected(true)) {
            FIH_PANIC;
        }

        err = esp_flash_encrypt_init();
        if (err != ESP_OK) {
            BOOT_LOG_ERR("Initialization of Flash Encryption key failed (%d)", err);
            FIH_PANIC;
        }
    }

    if (!flash_encryption_enabled) {
        err = esp_flash_encrypt_contents();
        if (err != ESP_OK) {
            BOOT_LOG_ERR("Encryption flash contents failed (%d)", err);
            FIH_PANIC;
        }

        err = esp_flash_encrypt_enable();
        if (err != ESP_OK) {
            BOOT_LOG_ERR("Enabling of Flash encryption failed (%d)", err);
            FIH_PANIC;
        }
    }

#ifdef CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER
    if (!esp_secure_boot_enabled() || !flash_encryption_enabled) {
        err = esp_efuse_batch_write_commit();
        if (err != ESP_OK) {
            BOOT_LOG_ERR("Error programming eFuses (err=0x%x).", err);
            FIH_PANIC;
        }
        assert(esp_secure_boot_enabled());
        BOOT_LOG_INF("Secure boot permanently enabled");
    }
#endif // CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER

    /* Step 7 (see above for full description):
     *   7) Reset system to ensure flash encryption cache resets properly.
     */
    if (!flash_encryption_enabled && esp_flash_encryption_enabled()) {
        BOOT_LOG_INF("Resetting with flash encryption enabled...");
        bootloader_reset();
    }
#endif

    BOOT_LOG_INF("Disabling RNG early entropy source...");
    bootloader_random_disable();

    /* Disable glitch reset after all the security checks are completed.
     * Glitch detection can be falsely triggered by EMI interference (high RF TX power, etc)
     * and to avoid such false alarms, disable it.
     */
    bootloader_ana_clock_glitch_reset_config(false);

#ifdef CONFIG_ESP_MULTI_PROCESSOR_BOOT
    /* Multi image independent boot
     * Boot on the second processor happens before the image0 boot
     */
    do_boot_appcpu(IMAGE_INDEX_1, PRIMARY_SLOT);
#endif

    do_boot(&rsp);

    while(1);
}
