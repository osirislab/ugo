from idc import AddStrucEx, AddStrucMember

from idaapi import * # mostly for constants

from . import Store

structs = Store()

size_to_flag = {
    1: FF_BYTE,
    2: FF_WORD,
    4: FF_DWRD,
    8: FF_QWORD,
    10: FF_TBYT,
    16: FF_OWRD,
    # 4: FF_FLOAT,
    # 8: FF_DOUBLE,
    # 10: FF_PACKREAL,
}

# the point of this function is to make logical argument order and
# also provide defaults.
"""
Define a new structure type

@param index: index of new structure type
              If another structure has the specified index,
              then index of that structure and all other
              structures will be incremented, freeing the specifed
              index. If index is == -1, then the biggest index
              number will be used.
              See GetFirstStrucIdx() for the explanation of
              structure indices and IDs.
@param name: name of the new structure type.
@param is_union: 0: structure
                 1: union

@return: -1 if can't define structure type because of
         bad structure name: the name is ill-formed or is
         already used in the program.
         otherwise returns ID of the new structure type

EXAMPLE
# sid = AddStrucEx(-1, name, 0) # go doesn't *really* use unions
"""
def add_struct(name, index=-1, is_union=0):
    return AddStrucEx(index, name, is_union)

"""
Add structure member

@param sid: structure type ID
@param name: name of the new member
@param offset: offset of the new member
               -1 means to add at the end of the structure
@param flag: type of the new member. Should be one of
             FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
@param typeid: if isStruc(flag) then typeid specifies the structure id for the member
               if isOff0(flag) then typeid specifies the offset base.
               if isASCII(flag) then typeid specifies the string type (ASCSTR_...).
               if isStroff(flag) then typeid specifies the structure id
               if isEnum(flag) then typeid specifies the enum id
               if isCustom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
               Otherwise typeid should be -1.
@param nbytes: number of bytes in the new member

@param target: target address of the offset expr. You may specify it as
               -1, ida will calculate it itself
@param tdelta: offset target delta. usually 0
@param reftype: see REF_... definitions

@note: The remaining arguments are allowed only if isOff0(flag) and you want
       to specify a complex offset expression

@return: 0 - ok, otherwise error code (one of STRUC_ERROR_*)

EXAMPLE
flag = (FF_DATA | size_to_flag[field.size]) & 0xFFFFFFFF
# This is to tell IDA what to label the field

err = AddStrucMember(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32)
err = AddStrucMember(sid, field.name, -1, flag, -1, field.size)
"""
def add_struct_member(struct_id, field_name, field_size=8, flags=0, field_index=-1, metadata=-1,
            target=-1, tdelta=0, reftype=REF_OFF64):
    """
    @param metadata: this is the flagid in the old AddStrucMember function. I didn't like the name
    """
    # this is to tell IDA what to label the field
    # we use the size_to_flag dict if no flags are specified, otherwise you
    # are expected to also provide that flag
    # FF_DATA flag is required
    flag = (FF_DATA | flags if flags else size_to_flag[field_size]) & 0xFFFFFFFF
    return AddStrucMember(struct_id, field_name, field_index, flag, metadata, field_size, target, tdelta, reftype)

"""
REF_OFF8    = idaapi.REF_OFF8    # 8bit full offset
REF_OFF16   = idaapi.REF_OFF16   # 16bit full offset
REF_OFF32   = idaapi.REF_OFF32   # 32bit full offset
REF_LOW8    = idaapi.REF_LOW8    # low 8bits of 16bit offset
REF_LOW16   = idaapi.REF_LOW16   # low 16bits of 32bit offset
REF_HIGH8   = idaapi.REF_HIGH8   # high 8bits of 16bit offset
REF_HIGH16  = idaapi.REF_HIGH16  # high 16bits of 32bit offset
REF_VHIGH   = idaapi.REF_VHIGH   # high ph.high_fixup_bits of 32bit offset (processor dependent)
REF_VLOW    = idaapi.REF_VLOW    # low  (32-ph.high_fixup_bits) of 32bit offset (processor dependent)
REF_OFF64   = idaapi.REF_OFF64   # 64bit full offset
REFINFO_RVA     = 0x10 # based reference (rva)
REFINFO_PASTEND = 0x20 # reference past an item it may point to an nonexistitng
                       # do not destroy alignment dirs
REFINFO_NOBASE  = 0x80 # offset base is a number
                       # that base have be any value
                       # nb: base xrefs are created only if base
                       # points to the middle of a segment
REFINFO_SUBTRACT = 0x0100 # the reference value is subtracted from
                          # the base value instead of (as usual)
                          # being added to it
REFINFO_SIGNEDOP = 0x0200 # the operand value is sign-extended (only
                          # supported for REF_OFF8/16/32/64)
"""