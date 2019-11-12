/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_atca.h"
#include "mgos_rpc.h"

#include "cryptoauthlib.h"

static void mgos_atca_get_config(struct mg_rpc_request_info *ri, void *cb_arg,
                                 struct mg_rpc_frame_info *fi,
                                 struct mg_str args) {
  uint8_t config[ATCA_ECC_CONFIG_SIZE];
  for (int i = 0; i < ATCA_ECC_CONFIG_SIZE / ATCA_BLOCK_SIZE; i++) {
    int offset = (i * ATCA_BLOCK_SIZE);
    ATCA_STATUS status =
        atcab_read_zone(ATCA_ZONE_CONFIG, 0 /* slot */, i /* block */,
                        0 /* offset */, config + offset, ATCA_BLOCK_SIZE);
    if (status != ATCA_SUCCESS) {
      mg_rpc_send_errorf(ri, 500, "Failed to read config zone block %d: 0x%02x",
                         i, status);
      ri = NULL;
      goto clean;
    }
  }

  mg_rpc_send_responsef(ri, "{config: %V}", config, sizeof(config));
  ri = NULL;

clean:
  (void) cb_arg;
  (void) args;
  (void) fi;
}

static void mgos_atca_set_config(struct mg_rpc_request_info *ri, void *cb_arg,
                                 struct mg_rpc_frame_info *fi,
                                 struct mg_str args) {
  uint8_t *config = NULL;
  uint32_t config_len = 0;
  json_scanf(args.p, args.len, ri->args_fmt, &config, &config_len);

  if (config_len != ATCA_ECC_CONFIG_SIZE) {
    mg_rpc_send_errorf(ri, 400, "Expected %d bytes, got %d",
                       (int) ATCA_ECC_CONFIG_SIZE, (int) config_len);
    ri = NULL;
    goto clean;
  }

  ATCA_STATUS status = atcab_write_config_zone(config);
  if (status != ATCA_SUCCESS) {
    mg_rpc_send_errorf(ri, 500, "Failed to set config: 0x%02x", status);
    ri = NULL;
    goto clean;
  }

  mg_rpc_send_responsef(ri, NULL);
  ri = NULL;

clean:
  if (config != NULL) free(config);
  (void) cb_arg;
  (void) fi;
}

static void mgos_atca_lock_zone(struct mg_rpc_request_info *ri, void *cb_arg,
                                struct mg_rpc_frame_info *fi,
                                struct mg_str args) {
  int zone = -1;
  json_scanf(args.p, args.len, ri->args_fmt, &zone);

  ATCA_STATUS status;
  switch (zone) {
    case LOCK_ZONE_CONFIG:
      status = atcab_lock_config_zone();
      break;
    case LOCK_ZONE_DATA:
      status = atcab_lock_data_zone();
      break;
    default:
      mg_rpc_send_errorf(ri, 403, "Invalid zone");
      ri = NULL;
      goto clean;
  }

  if (status != ATCA_SUCCESS) {
    mg_rpc_send_errorf(ri, 500, "Failed to lock zone %d: 0x%02x", zone, status);
    ri = NULL;
    goto clean;
  }

  mg_rpc_send_responsef(ri, NULL);
  ri = NULL;

clean:
  (void) cb_arg;
  (void) fi;
}

static void mgos_atca_set_key(struct mg_rpc_request_info *ri, void *cb_arg,
                              struct mg_rpc_frame_info *fi,
                              struct mg_str args) {
  int slot = -1, block = 0;
  uint8_t *key = NULL, *write_key = NULL;
  uint32_t key_len = 0, write_key_len = 0;
  uint32_t wk_slot = 0;
  bool is_ecc = false;
  json_scanf(args.p, args.len, ri->args_fmt, &slot, &block, &is_ecc, &key,
             &key_len, &write_key, &write_key_len, &wk_slot);

  if (slot < 0 || slot > 15) {
    mg_rpc_send_errorf(ri, 400, "Invalid slot");
    ri = NULL;
    goto clean;
  }

  if (write_key_len != 0 && write_key_len != ATCA_KEY_SIZE) {
    mg_rpc_send_errorf(ri, 400, "Expected %d bytes, got %d", ATCA_KEY_SIZE,
                       (int) key_len);
    ri = NULL;
    goto clean;
  }

  ATCA_STATUS status;
  if (is_ecc) {
    if (key_len > ATCA_PRIV_KEY_SIZE) {
      mg_rpc_send_errorf(ri, 400, "Expected %d bytes, got %d",
                         ATCA_PRIV_KEY_SIZE, (int) key_len);
      ri = NULL;
      goto clean;
    }
    uint8_t key_arg[4 + ATCA_PRIV_KEY_SIZE];
    memset(key_arg, 0, 4);
    memcpy(key_arg + 4, key, ATCA_PRIV_KEY_SIZE);
    status = atcab_priv_write(slot, key_arg, wk_slot, write_key);
  } else if (write_key_len > 0) {
    status = atcab_write_enc(slot, block, key, write_key, wk_slot);
  } else {
    status = atcab_write_zone(ATCA_ZONE_DATA, slot, block, 0, key, key_len);
  }
  if (status != ATCA_SUCCESS) {
    mg_rpc_send_errorf(ri, 500, "Failed to set key: 0x%02x", status);
    ri = NULL;
    goto clean;
  }

  mg_rpc_send_responsef(ri, NULL);
  ri = NULL;

clean:
  if (key != NULL) free(key);
  if (write_key != NULL) free(write_key);
  (void) cb_arg;
  (void) fi;
}

static void mgos_atca_get_or_gen_key(struct mg_rpc_request_info *ri,
                                     void *cb_arg, struct mg_rpc_frame_info *fi,
                                     struct mg_str args) {
  uint8_t pubkey[ATCA_PUB_KEY_SIZE];
  int slot = -1;
  json_scanf(args.p, args.len, ri->args_fmt, &slot);

  if (slot < 0 || slot > 15) {
    mg_rpc_send_errorf(ri, 400, "Invalid slot");
    ri = NULL;
    goto clean;
  }

  if (strcmp((const char *) cb_arg, "ATCA.GenKey") == 0) {
    ATCA_STATUS status = atcab_genkey(slot, pubkey);
    if (status != ATCA_SUCCESS) {
      mg_rpc_send_errorf(ri, 500, "Failed generate key on slot %d: 0x%02x",
                         slot, status);
      ri = NULL;
      goto clean;
    }
  } else {
    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey);
    if (status != ATCA_SUCCESS) {
      mg_rpc_send_errorf(ri, 500, "Failed get public key for slot %d: 0x%02x",
                         slot, status);
      ri = NULL;
      goto clean;
    }
  }

  mg_rpc_send_responsef(ri, "{pubkey: %V}", pubkey, sizeof(pubkey));
  ri = NULL;

clean:
  (void) fi;
}

static void mgos_atca_sign(struct mg_rpc_request_info *ri, void *cb_arg,
                           struct mg_rpc_frame_info *fi, struct mg_str args) {
  int slot = -1;
  uint8_t *digest = NULL;
  uint32_t digest_len = 0;
  json_scanf(args.p, args.len, ri->args_fmt, &slot, &digest, &digest_len);

  if (slot < 0 || slot > 15) {
    mg_rpc_send_errorf(ri, 400, "Invalid slot");
    ri = NULL;
    goto clean;
  }

  if (digest_len != 32) {
    mg_rpc_send_errorf(ri, 400, "Expected %d bytes, got %d", 32,
                       (int) digest_len);
    ri = NULL;
    goto clean;
  }

  uint8_t signature[ATCA_SIG_SIZE];
  ATCA_STATUS status = atcab_sign(slot, digest, signature);
  if (status != ATCA_SUCCESS) {
    mg_rpc_send_errorf(ri, 500, "Failed to sign: 0x%02x", status);
    ri = NULL;
    goto clean;
  }

  mg_rpc_send_responsef(ri, "{signature: %V}", signature, sizeof(signature));
  ri = NULL;

clean:
  if (digest != NULL) free(digest);
  (void) cb_arg;
  (void) fi;
}

static void mgos_atca_aes(struct mg_rpc_request_info *ri, void *cb_arg,
                          struct mg_rpc_frame_info *fi, struct mg_str args) {
  int slot = -1, block = 0;
  int mode = 0;
  uint32_t data_len = 0;
  uint8_t *data_in = NULL, *data_out = NULL;
  json_scanf(args.p, args.len, ri->args_fmt, &slot, &block, &mode, &data_in,
             &data_len);

  if (slot < 0 || slot > 15 || block < 0) {
    mg_rpc_send_errorf(ri, 400, "Invalid slot");
    ri = NULL;
    goto clean;
  }

  if (data_len % 16 != 0) {
    mg_rpc_send_errorf(ri, 400, "Data must be padded to AES block (16)");
    ri = NULL;
    goto clean;
  }

  data_out = (uint8_t *) malloc(data_len);
  if (data_out == NULL) {
    mg_rpc_send_errorf(ri, 500, "Out of memory");
    ri = NULL;
    goto clean;
  }

  for (uint32_t off = 0; off < data_len; off += 16) {
    ATCA_STATUS status;
    switch (mode) {
      case 0:
        status = atcab_aes_encrypt(slot, block, data_in + off, data_out + off);
        break;
      case 1:
        status = atcab_aes_decrypt(slot, block, data_in + off, data_out + off);
        break;
      default:
        mg_rpc_send_errorf(ri, 400, "Invalid mode");
        ri = NULL;
        goto clean;
    }
    if (status != ATCA_SUCCESS) {
      mg_rpc_send_errorf(ri, 500, "Failed to %s: 0x%02x",
                         (mode == 0 ? "encrypt" : "decrypt"), status);
      ri = NULL;
      goto clean;
    }
  }

  mg_rpc_send_responsef(ri, "{data: %V}", data_out, data_len);
  ri = NULL;

clean:
  free(data_in);
  free(data_out);
  (void) cb_arg;
  (void) fi;
}

bool mgos_rpc_service_atca_init(void) {
  struct mg_rpc *c = mgos_rpc_get_global();

  if (!mgos_sys_config_get_sys_atca_enable() || !mbedtls_atca_is_available()) {
    return true;
  }
  mg_rpc_add_handler(c, "ATCA.GetConfig", "", mgos_atca_get_config, NULL);
  mg_rpc_add_handler(c, "ATCA.SetConfig", "{config: %V}", mgos_atca_set_config,
                     NULL);
  mg_rpc_add_handler(c, "ATCA.LockZone", "{zone: %d}", mgos_atca_lock_zone,
                     NULL);
  mg_rpc_add_handler(
      c, "ATCA.SetKey",
      "{slot: %d, block: %d, ecc: %B, key: %V, wkey: %V, wkslot: %u}",
      mgos_atca_set_key, NULL);
  mg_rpc_add_handler(c, "ATCA.GenKey", "{slot: %d}", mgos_atca_get_or_gen_key,
                     "ATCA.GenKey");
  mg_rpc_add_handler(c, "ATCA.GetPubKey", "{slot: %d}",
                     mgos_atca_get_or_gen_key, "ATCA.GetPubKey");
  mg_rpc_add_handler(c, "ATCA.Sign", "{slot: %d, digest: %V}", mgos_atca_sign,
                     NULL);
  mg_rpc_add_handler(c, "ATCA.AES", "{slot: %d, block: %d, mode: %d, data: %V}",
                     mgos_atca_aes, NULL);
  return true;
}
