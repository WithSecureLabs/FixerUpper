def update_field(raw_message, flag, new_value, SOH="\x01"):
    msg_fields = raw_message.split(SOH)
    for i, field in enumerate(msg_fields):
        if field.startswith(flag + "="):
            msg_fields[i] = flag + "=" + str(new_value)
            break

    new_message = SOH.join(msg_fields)

    return new_message


def calculate_chksum(raw_message):
    checksum = 0
    for c in raw_message[:raw_message.index("10=")]:
        checksum += ord(c)
    checksum = str(checksum % 256).zfill(3)

    return checksum


def calculate_length(raw_message, SOH="\x01"):
    msg_fields = raw_message.split(SOH)
    length = len(SOH.join(msg_fields[2:-2]) + SOH)

    return length


if messageIsRequest:
    req_bytes = messageInfo.getRequest()
    req_obj = helpers.analyzeRequest(req_bytes)
    req_body = req_bytes[(req_obj.getBodyOffset()):].tostring()

    if req_body.startswith("8=FIX.4."):
        print("---- START REQUEST ----")

        message = req_body
        print(message.replace("\x01", "|"))

        message = update_field(message,  "9", calculate_length(message))
        message = update_field(message, "10", calculate_chksum(message))
        print(message.replace("\x01", "|"))

        new_req = helpers.buildHttpMessage(req_obj.getHeaders(), message)
        messageInfo.setRequest(new_req)

        print("---- END REQUEST ----")
