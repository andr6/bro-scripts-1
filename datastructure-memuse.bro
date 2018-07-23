# This script reports approximate memory footprints of a range of Bro
# script-level data structures, as reported by the val_size() BiF.

# Copyright (c) 2018, Christian Kreibich <christian@corelight.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the <project name> project.

function get_random_string(len: count): string
{
        local res = "";
        local fodder = "abcdefghijklmnopqrstuvwxyz";

        while (|res| < len) {
                res = fmt("%s%s", res, fodder[rand(|fodder|-1)]);
        }

        return res;
}

function print_header()
{
        local hdr = fmt("%-40s %-60s %s", "type", "detail", "size");
        print hdr;
        print string_fill(|hdr| + 10, "-")[:-1];
}

function print_val(v: any)
{
        print fmt("%-40s %-60s %d bytes", type_name(v), v, val_size(v));
}

function print_size_val(v: any, comment: string &default="")
{
        if (|comment| > 0)
                print fmt("%-40s %-60s %d bytes", type_name(v), fmt("(size %d, %s)", |v|, comment), val_size(v));
        else
                print fmt("%-40s %-60s %d bytes", type_name(v), fmt("(size %d)", |v|), val_size(v));
}

function print_count_sets()
{
        local s: set[count] = set();
        local ctr = 0;
        print_size_val(s);

        add s[ctr];
        print_size_val(s);

        while (|s| < 10) { ++ctr; add s[ctr]; }
        print_size_val(s);

        while (|s| < 100) { ++ctr; add s[ctr]; }
        print_size_val(s);

        while (|s| < 1000) { ++ctr; add s[ctr]; }
        print_size_val(s);

        while (|s| < 10000) { ++ctr; add s[ctr]; }
        print_size_val(s);
}

function print_string_sets()
{
        local s: set[string] = set();
        local val: string;
        local len = 100;
        print_size_val(s);

        add s[get_random_string(len)];
        print_size_val(s, fmt("strlen %s", len));
        
        while (|s| < 10) add s[get_random_string(len)];
        print_size_val(s, fmt("strlen %s", len));

        while (|s| < 100) add s[get_random_string(len)];
        print_size_val(s, fmt("strlen %s", len));

        while (|s| < 1000) add s[get_random_string(len)];
        print_size_val(s, fmt("strlen %s", len));

        while (|s| < 10000) add s[get_random_string(len)];
        print_size_val(s, fmt("strlen %s", len));
}

function print_count_tables()
{
        local t: table[count] of count = table();
        local ctr = 0;
        local val = 123;
        print_size_val(t);

        t[ctr] = val;
        print_size_val(t);

        while (|t| < 10) { ++ctr; t[ctr] = val; }
        print_size_val(t);

        while (|t| < 100) { ++ctr; t[ctr] = val; }
        print_size_val(t);

        while (|t| < 1000) { ++ctr; t[ctr] = val; }
        print_size_val(t);

        while (|t| < 10000) { ++ctr; t[ctr] = val; }
        print_size_val(t);
}

function print_count_string_tables(len: count)
{
        local t: table[count] of string = table();
        local ctr = 0;
        local val = string_fill(len, "a");
        print_size_val(t);

        t[ctr] = val;
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 10) { ++ctr; t[ctr] = val; }
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 100) { ++ctr; t[ctr] = val; }
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 1000) { ++ctr; t[ctr] = val; }
        print_size_val(t, fmt("strlen %d", len));
}

function print_string_count_tables(len: count)
{
        local t: table[string] of count = table();
        local val = 123;
        print_size_val(t);

        t[get_random_string(len)] = val;
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 10) { t[get_random_string(len)] = val; }
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 100) { t[get_random_string(len)] = val; }
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 1000) { t[get_random_string(len)] = val; }
        print_size_val(t, fmt("strlen %d", len));

        while (|t| < 10000) { t[get_random_string(len)] = val; }
        print_size_val(t, fmt("strlen %d", len));
}

type EnumType: enum { A, B, C };

type Record1: record {
        c: count &optional;
};

type Record2: record {
        c: count &optional;
        s: string &optional;
};

type Record3: record {
        c: count &optional;
        s: string &optional;
        a: addr &optional;
};

event bro_init()
{
        print_header();

        local bool_val: bool = T;
        print_val(bool_val);

        local count_val: count = 1;
        print_val(count_val);

        local int_val: int = -1;
        print_val(int_val);
        
        local double_val: double = 123.456;
        print_val(double_val);

        local time_val = network_time();
        print_val(time_val);

        local interval_val = 20sec;
        print_val(interval_val);

        local port_val = 80/tcp;
        print_val(port_val);

        local addr_v4_val = 1.2.3.4;
        print_val(addr_v4_val);

        local addr_v6_val = [fe80::16bd:4390:60ae:3a7f];
        print_val(addr_v6_val);

        local subnet_v4_val = 1.2.3.4/16;
        print_val(subnet_v4_val);

        local subnet_v6_val = [fe80::16bd:4390:60ae:3a7f]/16;
        print_val(subnet_v6_val);

        local enum_val: EnumType = A;
        print_val(enum_val);

        local string_1_val = "a";
        print_size_val(string_1_val);
        
        local string_10_val = string_fill(10, "a");
        print_size_val(string_10_val);
        
        local string_100_val = string_fill(100, "a");
        print_size_val(string_100_val);
        
        local string_1000_val = string_fill(1000, "a");
        print_size_val(string_1000_val);
        
        local string_10000_val = string_fill(10000, "a");
        print_size_val(string_10000_val);

        local pattern_1_val = /a/;
        print_val(pattern_1_val);

        local pattern_2_val = /a.a.a.a.a./;
        print_val(pattern_2_val);

        local pattern_3_val = /(a.a)*.a.(a.a.)+/;
        print_val(pattern_3_val);

        local rec_1_val = Record1();
        print_val(rec_1_val);

        rec_1_val$c = 123;
        print_val(rec_1_val);

        local rec_2_val = Record2();
        print_val(rec_2_val);

        rec_2_val$c = 123;
        print_val(rec_2_val);

        rec_2_val$s = "aaaaaaaaaa";;
        print_val(rec_2_val);

        local rec_3_val = Record3();
        print_val(rec_3_val);

        rec_3_val$c = 123;
        print_val(rec_3_val);

        rec_3_val$s = "aaaaaaaaaa";;
        print_val(rec_3_val);

        rec_3_val$a = 1.2.3.4;
        print_val(rec_3_val);
        
        print_count_sets();
        print_string_sets();
        print_count_tables();
        print_count_string_tables(10);
        print_count_string_tables(100);
        print_string_count_tables(10);
        print_string_count_tables(100);
}
