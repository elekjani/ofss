#define MAX_PP_NUM 100

struct template_msg_data {
};

static void
template_packetproc_mod(struct packetproc *packetproc, uint32_t type ,uint32_t proc_id ,uint16_t command, void *data);

static int 
template_unpack(uint8_t *src, uint8_t *msg, enum ofp_type type, char *errbuf);

static int
template_pack(uint8_t *msg, uint8_t *buf, enum ofp_type type);

static bool
template_process_msg(void *pp_, struct list_node *cmd_);

struct PP_types_list*
template_packetproc_init(struct packetproc *packetproc) {
    struct PP_types_list *PP_type = malloc(sizeof(struct PP_types_list));
    PP_type->PP_type              = TEMPLATE;
    PP_type->mod_cb               = template_packetproc_mod;
    PP_type->unpack_cb            = template_unpack;
    PP_type->pack_cb              = template_pack;
    PP_type->PP_msg_data_len      = sizeof(struct template_msg_data);
    PP_type->current_pp_num       = 0;
    PP_type->max_pp_num           = MAX_PP_NUM;
    PP_type->prev                 = NULL;
    PP_type->next                 = NULL;
    logger_log(packetproc->logger, LOG_DEBUG, "Init \"Template\" packetprocessors. (%d)", DEFAULT);

    return PP_type;
}
