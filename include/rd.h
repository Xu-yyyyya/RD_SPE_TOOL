#ifdef __cplusplus
extern "C" {
#endif

void rd_start(const char *tag);
void rd_stop();
void rd_tag_addr(const char *tag, void *start, void *end);
void rd_tag_from_maps(const char *tag, const char *file);

#ifdef __cplusplus
}
#endif


