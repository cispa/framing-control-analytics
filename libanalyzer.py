from urllib.parse import ParseResult, urlparse
import sys


def is_valid_origin(uo: ParseResult) -> bool:
    """
    Checks if the accessed URL is a valid URL

    :param uo: ParseResult returned by urlparse of the current URL
    :return: true if URL is valid else false
    """
    try:
        valid_scheme = uo.scheme == 'http' or uo.scheme == 'https'
        valid_hostname = uo.hostname != '' and (not uo.hostname.startswith("*."))
        return valid_scheme and valid_hostname
    except Exception as e:
        print("!!! is_valid_origin failed on:", str(uo))
        print(e)
        return False


def parse_xfo(s: str) -> str or None:
    """
    :param s: Raw XFO header value as string
    :return: Stripped string or None
    """
    if s == 'WARN_NO_HEADER':
        return None
    return s.strip()


def normalize_xfo(v: str, o: str) -> str or tuple:
    """
    Normalization of the XFO header according to the Paper

    :param v: Value of the XFO header
    :param o: Original accessed URL
    :return: Normalized XFO header value
    """
    if o is not None and o.startswith('//'):
        o = 'https:' + o

    uo = urlparse(o)
    if not is_valid_origin(uo):
        print("Invalid origin in call to normalize_xfo for", o)
        return "JUNK"

    v = v.lower()
    # If only same origin framing is allowed
    if v == "sameorigin":
        return "SAMEORIGIN", (uo.scheme, uo.hostname)
    # If framing is denied
    if v == "deny":
        return "DENY"
    # If other origin is whitelisted
    if v.startswith("allow-from "):
        tokens = v.split(' ')
        ue = urlparse(tokens[1])
        if len(tokens) == 2 and tokens[0] == "allow-from" and is_valid_origin(ue):
            return "ALLOW-FROM", (ue.scheme, ue.hostname)
        else:
            return "ALLOW-JUNK"
    return "JUNK"


def parse_csp(s: str) -> str or None:
    """
    :param s: Raw CSP header value as string
    :return: Stripped list of tokens in the CSP string or None
    """
    if s == 'WARN_NO_HEADER':
        return None
    return s.strip().split()


def normalize_csp(v: list, o: str) -> str or tuple:
    """
    Normalization of the CSP header according to the Paper

    :param v: List of values of the CSP header
    :param o: Original accessed URL
    :return: List of normalized CSP values
    """

    if o is not None and o.startswith('//'):
        o = 'https:' + o

    uo = urlparse(o)
    if not is_valid_origin(uo):
        print("Invalid origin in call to normalize_csp for", o)
        return "JUNK"

    nv = []
    for e in v:
        e = e.lower()
        if e == '*':
            nv.append('*')
        elif e == "\'none\'":
            nv.append('none')
        elif e == "\'self\'":
            nv.append((uo.scheme, uo.hostname))
        elif e == "http:":
            nv.append(("http", "*"))
        elif e == "https:":
            nv.append(("https", "*"))
        else:
            ue = urlparse(e)
            if ue.scheme == '':
                nv.append((uo.scheme, e))
            else:
                nv.append((ue.scheme, ue.hostname))
    return nv


def t_firefox(p: dict, orig: str) -> list:
    """
    Semantics of enforcement for Firefox (specification)

    :param p: Dictionary of policies
    :param orig: Original url
    :return: List of enforced values
    """
    pol = {'csp': [], 'xfo': []}

    # Normalization for XFO
    parsed_xfo = [x.split(',') for x in p['xfo']]
    parsed_xfo = [y for x in parsed_xfo for y in x]
    for x in parsed_xfo:
        px = parse_xfo(x)
        if px is not None:
            pol['xfo'].append(normalize_xfo(px, orig))

    # Normalization for CSP
    for c in p['csp']:
        pc = parse_csp(c)
        if pc is not None:
            pol['csp'].append(normalize_csp(pc, orig))

    if len(pol["csp"]) > 0:
        return pol["csp"][0]

    if len(pol["xfo"]) > 0:
        res = "*"
        for x in pol["xfo"]:
            if x == "JUNK":
                res = meet(res, "*")
            elif x == "DENY" or x == "ALLOW-JUNK":
                res = meet(res, "none")
            else:
                res = meet(res, x[1])
        return [res]
    else:
        return ["*"]


def t_chrome(p: dict, orig: str) -> list:
    """
    Semantics of enforcement for Chrome, Chrome for Android, Safari, Safari for iOS, Samsung Internet, UC Browser

    :param p: Dictionary of policies
    :param orig: Original url
    :return: List of enforced values
    """
    pol = {'csp': [], 'xfo': []}

    # Normalization for XFO
    parsed_xfo = [x.split(',') for x in p['xfo']]
    parsed_xfo = [y for x in parsed_xfo for y in x]
    for x in parsed_xfo:
        px = parse_xfo(x)
        if px is not None:
            pol['xfo'].append(normalize_xfo(px, orig))

    # Normalization for CSP
    for c in p['csp']:
        pc = parse_csp(c)
        if pc is not None:
            pol['csp'].append(normalize_csp(pc, orig))

    if len(pol["csp"]) > 0:
        return pol["csp"][0]

    if len(pol["xfo"]) > 0:
        res = "*"
        for x in pol["xfo"]:
            if x == "JUNK" or x == "ALLOW-JUNK" or x[0] == "ALLOW-FROM":
                res = meet(res, "*")
            elif x == "DENY":
                res = meet(res, "none")
            else:
                res = meet(res, x[1])
        return [res]
    else:
        return ["*"]


def t_opera_mini(p: dict, orig: str) -> list:
    """
    Semantics of enforcement for Opera Mini

    :param p: Dictionary of policies
    :param orig: Original url
    :return: List of enforced values
    """
    pol = {'csp': [], 'xfo': []}

    # Normalization for XFO
    for x in p['xfo']:
        px = parse_xfo(x)
        if px is not None:
            pol['xfo'].append(normalize_xfo(px, orig))

    if len(pol["xfo"]) > 0:
        x = pol["xfo"][0]

        if x == "JUNK" or x == "ALLOW-JUNK" or x[0] == "ALLOW-FROM":
            res = "*"
        elif x == "DENY":
            res = "none"
        else:
            res = x[1]
        return [res]
    else:
        return ["*"]


def t_edge(p: dict, orig: str) -> list:
    """
    Semantics of enforcement for Edge

    :param p: Dictionary of policies
    :param orig: Original url
    :return: List of enforced values
    """
    pol = {'csp': [], 'xfo': []}

    # Normalization for CSP
    for c in p['csp']:
        pc = parse_csp(c)
        if pc is not None:
            pol['csp'].append(normalize_csp(pc, orig))

    # Normalization for XFO
    for x in p['xfo']:
        px = parse_xfo(x)
        if px is not None:
            pol['xfo'].append(normalize_xfo(px, orig))

    if len(pol["csp"]) > 0:
        return pol["csp"][0]

    if len(pol["xfo"]) > 0:
        x = pol["xfo"][0]

        if x == "JUNK":
            res = "*"
        elif x == "DENY" or x == "ALLOW-JUNK":
            res = "none"
        else:
            res = x[1]
        return [res]
    else:
        return ["*"]


def t_explorer(p: dict, orig: str) -> list:
    """
    Semantics of enforcement for Internet Explorer

    :param p: Dictionary of policies
    :param orig: Original url
    :return: List of enforced values
    """
    pol = {'csp': [], 'xfo': []}

    # Normalization for XFO
    for x in p['xfo']:
        px = parse_xfo(x)
        if px is not None:
            pol['xfo'].append(normalize_xfo(px, orig))

    if len(pol["xfo"]) > 0:
        x = pol["xfo"][0]

        if x == "JUNK":
            res = "*"
        elif x == "DENY" or x == "ALLOW-JUNK":
            res = "none"
        else:
            res = x[1]
        return [res]
    else:
        return ["*"]


def translate(p: dict, b: str, orig: str) -> list:
    """
    :param p: Dictionary of policies
    :param b: User-Agent string
    :param orig: Original URL
    :return:
    """
    if b == "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0":
        return t_firefox(p, orig)
    if b in [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-G960U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.4 Chrome/67.0.3396.87 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 7.0; es-LA; Moto C Build/NRD90M.068) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.108 UCBrowser/12.9.5.1146 Mobile Safari/537.36"]:
        return t_chrome(p, orig)
    if b == "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko":
        return t_explorer(p, orig)
    if b == "Opera/9.80 (Android; Opera Mini/12.0.1987/37.7327; U; pl) Presto/2.12.423 Version/12.16":
        return t_opera_mini(p, orig)
    if b == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763":
        return t_edge(p, orig)
    else:
        print("Unsupported browser in call to translate!")
        sys.exit()


def leq_host(h1: str, h2: str) -> bool:
    """
    :param h1: Value for Host A
    :param h2: Value for Host B
    :return: Equality match
    """
    if h1 == h2:
        return True
    if h2 == '*':
        return True
    if h1 == '*':
        return False
    tokens1 = h1.split('.')
    tokens2 = h2.split('.')
    if tokens1[0] == '*':
        return tokens2[0] == '*' and h1.endswith('.' + '.'.join(tokens2[1:]))
    elif tokens2[0] == '*':
        return h1.endswith('.' + '.'.join(tokens2[1:]))
    return False


def leq_exp(e1: str, e2: str) -> bool:
    """
    :param e1: Value for Expression A
    :param e2: Value for Expression B
    :return: Equality match
    """
    if e1 == e2:
        return True
    if e2 == '*':
        return True
    if e1 == '*':
        return False
    if e2 == 'none':
        return False
    if e1 == 'none':
        return True
    return e1[0] == e2[0] and leq_host(e1[1], e2[1])


def leq_val(v1: list, v2: list) -> bool:
    """
    :param v1: List of expressions A
    :param v2: List of expressions B
    :return: Equality match
    """
    for e1 in v1:
        found = False
        for e2 in v2:
            if leq_exp(e1, e2):
                found = True
        if not found:
            return False
    return True


def meet(e1: str, e2: str) -> str:
    """
    :param e1: Value for Expression A
    :param e2: Value for Expression B
    :return: Meeting Value
    """
    if leq_exp(e1, e2):
        return e1
    if leq_exp(e2, e1):
        return e2
    return 'none'


def just_xfo(b: str) -> bool:
    """
    :param b: User-Agent string
    :return: true if only XFO is supported else false
    """
    return b in ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                 "Opera/9.80 (Android; Opera Mini/12.0.1987/37.7327; U; pl) Presto/2.12.423 Version/12.16"]


def find_inconsistencies(p: dict, orig: str) -> dict:
    """
    Lookup the semantic inconsistency between XFO and CSP

    :param p: Dictionary of policies
    :param orig: Original URL
    :return: Dictionary of inconsistencies
    """
    semantics = {"xfo": [], "csp": []}
    b_xfo = []
    b_csp = []

    for b in p:
        if just_xfo(b):
            b_xfo.append(b)
        else:
            b_csp.append(b)

    for b in b_xfo + b_csp:

        v = translate(p[b], b, orig)

        if just_xfo(b):
            key = "xfo"
        else:
            key = "csp"

        semantics[key].append(v)

    # remove duplicates
    no_dup_xfo = []
    [no_dup_xfo.append(x) for x in semantics["xfo"] if x not in no_dup_xfo]
    no_dup_csp = []
    [no_dup_csp.append(x) for x in semantics["csp"] if x not in no_dup_csp]
    semantics["xfo"] = no_dup_xfo
    semantics["csp"] = no_dup_csp

    return semantics


def is_inconsistent(s: dict) -> bool:
    """
    Checks if policies are inconsistent

    :param s: Dictionary of policies
    :return: true if inconsistent else false
    """
    if len(s["xfo"]) > 1 or len(s["csp"]) > 1:
        return True
    if len(s["xfo"]) == 1 and len(s["csp"]) == 1:
        v1 = s["xfo"][0]
        v2 = s["csp"][0]
        return not leq_val(v1, v2) or not leq_val(v2, v1)
    return False


def is_sec_oriented(s: dict) -> bool:
    """
    Checks if policies are security oriented

    :param s: Dictionary of policies
    :return: true if security oriented else false
    """
    if len(s["xfo"]) > 1 or len(s["csp"]) > 1:
        return False
    if len(s["xfo"]) == 0 or len(s["csp"]) == 0:
        return True
    v1 = s["xfo"][0]
    v2 = s["csp"][0]
    return leq_val(v1, v2)


def is_comp_oriented(s: dict) -> bool:
    """
    Checks if policies are compatibility oriented

    :param s: Dictionary of policies
    :return: true if compatibility oriented else false
    """
    if len(s["xfo"]) > 1 or len(s["csp"]) > 1:
        return False
    if len(s["xfo"]) == 0 or len(s["csp"]) == 0:
        return True
    v1 = s["xfo"][0]
    v2 = s["csp"][0]
    return leq_val(v2, v1)
