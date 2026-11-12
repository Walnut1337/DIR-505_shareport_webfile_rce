/*
 * webfile_cgi.cgi 1.10B02
 * MD5 28cb86cc8b93ba2e4a47c6261403b5ce
 *
 * Reconstructed behavior of get_input_entries() from the 1.10B02 binary.
 * The parser reads CONTENT_LENGTH bytes from stdin and writes each form
 * name/value byte into a caller-supplied stack buffer using a fixed 0x425
 * stride. Neither the field index nor the byte offset is bounds-checked.
 */

int get_input_entries(char *buf, int content_length)
{
    int field = 0;      /* iVar5: 0x425-stride entry index */
    int offset = 0;     /* iVar6: byte offset inside the current field */
    int in_value = 0;   /* bVar1: after '=' */
    int ch;

    while (content_length-- > 0) {
        ch = getc(stdin);

        if (ch == '=') {
            in_value = 1;
            offset = 0;
        } else if (ch == '&') {
            field++;
            offset = 0;
            in_value = 0;
        } else {
            int next = offset + 1;
            if (in_value)
                buf[offset + field * 0x425 + 0x24] = (char)ch;
            else
                buf[offset + field * 0x425] = (char)ch;
            offset = next;
        }
    }

    /* post-processing loops over field entries; no global length check */
    return field + 1;
}
