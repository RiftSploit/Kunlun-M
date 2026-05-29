# -*- coding: utf-8 -*-

"""
    scanner
    ~~~~~~~

    扫描调度与任务管理

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import json
import os
import asyncio
import traceback
import portalocker

from core.rule import Rule
from core.matcher import VulnerabilityMatcher as Core
from core.rule_generator import NewCore
from Kunlun_M import const
from Kunlun_M.const import VulnerabilityResult
from utils.utils import show_context
from utils.file import FileParseAll
from utils.log import logger
from utils.status import get_scan_id

from Kunlun_M.settings import RUNNING_PATH
from web.index.models import ScanResultTask, NewEvilFunc
from web.index.models import get_resultflow_class, check_update_or_new_scanresult


class Running:
    def __init__(self, sid):
        self.sid = sid

    def init_list(self, data=None):
        """
        Initialize asid_list file.
        :param data: list or a string
        :return:
        """
        file_path = os.path.join(RUNNING_PATH, '{sid}_list'.format(sid=self.sid))
        if not os.path.exists(file_path):
            if isinstance(data, list):
                with open(file_path, 'w') as f:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': len(data),
                    }))
            else:
                with open(file_path, 'w') as f:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': 1,
                    }))

    def list(self, data=None):
        file_path = os.path.join(RUNNING_PATH, '{sid}_list'.format(sid=self.sid))
        if data is None:
            with open(file_path, 'r') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
                return json.loads(result)
        else:
            with open(file_path, 'r+') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.read()
                if result == '':
                    result = {'sids': {}}
                else:
                    result = json.loads(result)
                result['sids'][data[0]] = data[1]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(result))

    def status(self, data=None):
        file_path = os.path.join(RUNNING_PATH, '{sid}_status'.format(sid=self.sid))
        if data is None:
            with open(file_path) as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data)
            with open(file_path, 'w') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                f.writelines(data)

    def data(self, data=None):

        file_path = os.path.abspath(RUNNING_PATH + '/{sid}_data'.format(sid=self.sid))

        if data is None:
            with open(file_path) as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data, sort_keys=True)
            with open(file_path, 'w+') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                f.writelines(data)

    def is_file(self, is_data=False):
        if is_data:
            ext = 'data'
        else:
            ext = 'status'
        file_path = os.path.join(RUNNING_PATH, '{sid}_{ext}'.format(sid=self.sid, ext=ext))
        return os.path.isfile(file_path)


def score2level(score):
    level_score = {
        'CRITICAL': [9, 10],
        'HIGH': [6, 7, 8],
        'MEDIUM': [3, 4, 5],
        'LOW': [1, 2]
    }
    score = int(score)
    level = None
    for l in level_score:
        if score in level_score[l]:
            level = l
    if level is None:
        return 'Unknown'
    else:
        if score < 10:
            score_full = '0{s}'.format(s=score)
        else:
            score_full = score

        a = '{s}{e}'.format(s=score * '■', e=(10 - score) * '□')
        return '{l}-{s}: {ast}'.format(l=level[:1], s=score_full, ast=a)


def scan_single(target_directory, single_rule, files=None, language=None, tamper_name=None, is_unconfirm=False,
                newcore_function_list=[]):
    try:
        return SingleRule(target_directory, single_rule, files, language, tamper_name, is_unconfirm,
                          newcore_function_list).process()
    except Exception:
        raise


def scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0, files=None, tamper_name=None, is_unconfirm=False):
    r = Rule(language)
    vulnerabilities = r.vulnerabilities
    rules = r.rules(special_rules)
    find_vulnerabilities = []
    newcore_function_list = {}

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                res.file_path = res.file_path
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    async def start_scan(target_directory, rule, files, language, tamper_name):
        result = scan_single(target_directory, rule, files, language, tamper_name, is_unconfirm, newcore_function_list)
        store(result)

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
    print('[CI] DEBUG: Loaded rules: {}'.format(','.join(sorted(rules.keys()))))
    push_rules = []
    scan_list = []

    for idx, single_rule in enumerate(sorted(rules.keys())):

        # init rule class
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False and len(rules) != 1:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.svid))
            continue
        # SR(Single Rule)
        logger.debug("""[PUSH] [CVI_{cvi}] {idx}.{vulnerability}({language})""".format(
            cvi=rule.svid,
            idx=idx,
            vulnerability=rule.vulnerability,
            language=rule.language
        ))
        # result = scan_single(target_directory, rule, files, language, tamper_name)
        scan_list.append(start_scan(target_directory, rule, files, language, tamper_name))
        # store(result)

    # Python 3.11+ no longer recommends manual global event-loop management.
    # Use asyncio.run for compatibility with modern Python (including 3.13+).
    async def _run_scan_list(tasks):
        await asyncio.gather(*tasks)

    asyncio.run(_run_scan_list(scan_list))

    # print
    data = []
    data2 = []
    trigger_rules = []
    for idx, x in enumerate(find_vulnerabilities):

        db_params = x.to_db_params(target_directory=target_directory)
        trigger = db_params['vulfile_path']
        code_content = db_params['source_code']
        commit = u'@{author}'.format(author=x.commit_author)
        row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit,
               code_content, x.analysis]
        row2 = [idx + 1, x.chain]

        # save to database
        sr = check_update_or_new_scanresult(scan_task_id=a_sid, is_active=True, **db_params)

        if sr:
            for chain in x.chain:
                if type(chain) == tuple:
                    ResultFlow = get_resultflow_class(int(a_sid))
                    node_source = show_context(chain[2], chain[3], is_back=True)

                    rf = ResultFlow(vul_id=sr.id, node_type=chain[0], node_content=chain[1],
                                    node_path=chain[2], node_source=node_source, node_lineno=chain[3])
                    rf.save()

        data.append(row)
        data2.append(row2)

    for new_function_name in newcore_function_list:
        # add new evil func in database
        for svid in newcore_function_list[new_function_name]["svid"]:
            if new_function_name and newcore_function_list[new_function_name]["origin_func_name"]:

                nf = NewEvilFunc(svid=svid, scan_task_id=get_scan_id(), func_name=new_function_name,
                                 origin_func_name=newcore_function_list[new_function_name]["origin_func_name"])
                nf.save()

    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
                'language': ",".join(language),
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(rules),
                'trigger_rules': len(trigger_rules),
                'target_directory': target_directory
            }
        })
    return True


class SingleRule(object):
    def __init__(self, target_directory, single_rule, files, language=None, tamper_name=None, is_unconfirm=False,
                 newcore_function_list=[]):
        self.target_directory = target_directory
        self.sr = single_rule
        self.files = files
        self.languages = language
        self.lan = self.sr.language.lower()
        self.tamper_name = tamper_name
        self.is_unconfirm = is_unconfirm
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

        # new core function list
        self.newcore_function_list = newcore_function_list

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        if self.sr.match_mode == const.mm_regex_only_match:
            # 当所有match都满足时成立，当单一unmatch满足时，不成立
            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            result = []
            new_result = []
            old_result = 0

            try:
                if matchs:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)

                    for match in matchs:

                        new_result = f.multi_grep(match)

                        if old_result == 0:
                            old_result = new_result
                            result = new_result
                            continue

                        old_result = result
                        result = []

                        for old_vul in old_result:
                            for new_vul in new_result:
                                if new_vul[0] == old_vul[0]:
                                    result.append(old_vul)

                    for unmatch in unmatchs:
                        uresults = f.multi_grep(unmatch)

                        for uresult in uresults:
                            for vul in result:
                                if vul[0] == uresult[0]:
                                    result.remove(vul)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.mm_regex_param_controllable:
            # 自定义匹配，调用脚本中的匹配函数匹配参数
            match = self.sr.match

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    result = f.grep(match)
                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode in (const.mm_function_param_controllable,
                                     const.mm_java_function_param_controllable):
            # 函数匹配，直接匹配敏感函数，然后处理敏感函数的参数即可
            # param controllable
            
            match = None
            
            if hasattr(self.sr, 'match') and self.sr.match:
                if self.sr.match_mode == const.mm_java_function_param_controllable:
                    # Java 专用模式：match 字段直接作为 grep 正则，不套 fpc 模板
                    match = self.sr.match
                elif (hasattr(self.sr, 'vul_function') and
                      isinstance(self.sr.vul_function, list) and
                      len(self.sr.vul_function) > 0):
                    # 有 vul_function → match 作为完整正则
                    match = self.sr.match
                else:
                    # 传统 PHP/JS 模式：match 是函数名，用 fpc 模板
                    if '|' in self.sr.match:
                        match = const.fpc_multi.replace('[f]', self.sr.match)
                        if self.sr.keyword == 'is_echo_statement':
                            match = const.fpc_echo_statement_multi.replace('[f]', self.sr.match)
                    else:
                        match = const.fpc_single.replace('[f]', self.sr.match)
                        if self.sr.keyword == 'is_echo_statement':
                            match = const.fpc_echo_statement_single.replace('[f]', self.sr.match)

                    if self.sr.language.lower() == "javascript":
                        match = const.fpc_loose.replace('[f]', self.sr.match)

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    
                    # match 可能是字符串或列表
                    if isinstance(match, list):
                        # 多条正则，分别 grep 合并去重
                        all_results = []
                        seen = set()
                        for m in match:
                            r = f.grep(m)
                            if r:
                                for item in r:
                                    if item not in seen:
                                        seen.add(item)
                                        all_results.append(item)
                        result = all_results if all_results else None
                    else:
                        result = f.grep(match)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.mm_regex_return_regex:
            # 回馈式正则匹配，将匹配到的内容返回，然后合入正则表达式

            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            matchs_name = self.sr.match_name
            black_list = self.sr.black_list

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.multi_grep_name(matchs, unmatchs, matchs_name, black_list)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.sp_crx_keyword_match:
            # 针对crx研究的keyword匹配，先以sp crx作为入口，逐渐思考普适性

            keyword = self.sr.keyword
            match = self.sr.match
            unmatch = self.sr.unmatch

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.special_crx_keyword_match(keyword, match, unmatch)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.file_path_regex_match:
            # 针对敏感文件名的匹配检查

            match = self.sr.match

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.find_keyword_file_or_path(match)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.mm_framework_dependency:
            # 框架依赖版本检测: 解析 pom.xml/build.gradle, 版本范围匹配 + 配置特征二次确认
            from utils.pom_parser import check_framework_dependency, search_code_patterns

            result = []

            try:
                framework_deps = getattr(self.sr, 'framework_deps', [])
                config_patterns = getattr(self.sr, 'config_patterns', [])
                exclude_patterns = getattr(self.sr, 'exclude_patterns', [])

                for dep_config in framework_deps:
                    matched_deps = check_framework_dependency(self.target_directory, dep_config)

                    for matched in matched_deps:
                        pom_path = matched['pom']
                        version = matched['version']
                        cve = matched.get('cve', '')
                        desc = matched.get('description', '')

                        # 二次确认: config_patterns
                        if config_patterns:
                            config_files = search_code_patterns(self.target_directory, config_patterns)
                            if not config_files:
                                logger.debug(f'[FRAMEWORK] config patterns not found, skip {cve}')
                                continue

                        # 排除检查: exclude_patterns
                        if exclude_patterns:
                            exclude_files = search_code_patterns(self.target_directory, exclude_patterns)
                            if exclude_files:
                                logger.debug(f'[FRAMEWORK] exclude patterns found, skip {cve}')
                                continue

                        # 格式化为统一的 result tuple: (file_path, line_number, match_text)
                        match_text = f"{dep_config['group_id']}:{dep_config['artifact_id']}:{version}"
                        if cve:
                            match_text += f" ({cve})"
                        result.append((pom_path, "0", match_text))

                if not result:
                    result = None
            except Exception as e:
                logger.debug(f'framework-dependency match exception ({e})')
                logger.debug(traceback.format_exc())
                return None

        else:
            logger.warning('Exception match mode: {m}'.format(m=self.sr.match_mode))
            result = None

        try:
            result = result.decode('utf-8')
        except AttributeError as e:
            pass

        return result

    def process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        origin_results = self.origin_results()
        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr.svid))
            print('[CI] DEBUG: [CVI-{cvi}] origin_results=None, match_mode={mm}, match={m}'.format(
                cvi=self.sr.svid, mm=self.sr.match_mode, m=getattr(self.sr, 'match', '?')))
            return None
        else:
            print('[CI] DEBUG: [CVI-{cvi}] origin_results count={cnt}, match_mode={mm}'.format(
                cvi=self.sr.svid, cnt=len(origin_results), mm=self.sr.match_mode))
            for i, ov in enumerate(origin_results[:5]):
                print('[CI] DEBUG: [CVI-{cvi}] origin[{i}]: {ov}'.format(cvi=self.sr.svid, i=i, ov=ov))

        # framework-dependency 模式: 直接生成结果，不需要 AST 分析
        if self.sr.match_mode == const.mm_framework_dependency:
            for index, origin_vulnerability in enumerate(origin_results):
                vulnerability = VulnerabilityResult.from_match(origin_vulnerability, svid=self.sr.svid,
                                                                language=self.sr.language,
                                                                rule_name=self.sr.vulnerability,
                                                                author=self.sr.author)
                if vulnerability:
                    cve_info = origin_vulnerability[2] if len(origin_vulnerability) > 2 else ''
                    vulnerability.analysis = f"Framework dependency vulnerability: {cve_info}"
                    vulnerability.chain = [("Dependency", cve_info, origin_vulnerability[0], 0)]
                    self.rule_vulnerabilities.append(vulnerability)
            logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                            count=len(self.rule_vulnerabilities)))
            return self.rule_vulnerabilities

        origin_vulnerabilities = origin_results
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            logger.debug(
                '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr.svid, line=": ".join(list(origin_vulnerability))))
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue
            vulnerability = VulnerabilityResult.from_match(origin_vulnerability, svid=self.sr.svid,
                                                            language=self.sr.language,
                                                            rule_name=self.sr.vulnerability,
                                                            author=self.sr.author)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False
            try:
                datas = Core(self.target_directory, vulnerability, self.sr, 'project name',
                             ['whitelist1', 'whitelist2'], test=is_test, index=index,
                             files=self.files, languages=self.languages, tamper_name=self.tamper_name,
                             is_unconfirm=self.is_unconfirm).scan()

                data = ""

                if len(datas) == 3:
                    is_vulnerability, reason, data = datas

                    if "New Core" not in reason:
                        code = "Code: {}".format(origin_vulnerability[2].strip(" "))
                        file_path = os.path.normpath(origin_vulnerability[0])
                        data.insert(1, ("NewScan", code, origin_vulnerability[0], origin_vulnerability[1]))

                elif len(datas) == 2:
                    is_vulnerability, reason = datas
                else:
                    is_vulnerability, reason = False, "Unpack error"

                print('[CI] DEBUG: [CVI-{cvi}] Core.scan() result: is_vul={iv}, reason={r}'.format(
                    cvi=self.sr.svid, iv=is_vulnerability, r=reason))

                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr.svid, code=reason))
                    vulnerability.analysis = reason
                    vulnerability.chain = data
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    if reason == 'New Core':  # 新的规则

                        logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules init'.format(cvi=self.sr.svid))
                        new_rule_vulnerabilities = NewCore(self.sr, self.target_directory, data, self.files, 0,
                                                           languages=self.languages, tamper_name=self.tamper_name,
                                                           is_unconfirm=self.is_unconfirm,
                                                           newcore_function_list=self.newcore_function_list)

                        if len(new_rule_vulnerabilities) > 0:
                            self.rule_vulnerabilities.extend(new_rule_vulnerabilities)

                    else:
                        logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception:
                print('[CI] DEBUG: [CVI-{cvi}] EXCEPTION in Core.scan(): {e}'.format(
                    cvi=self.sr.svid, e=traceback.format_exc()))
                raise
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                        count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities
