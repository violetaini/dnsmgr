<?php

namespace app\lib\dns;

use app\lib\DnsInterface;
use app\lib\client\HuaweiCloud;
use Exception;

class huawei implements DnsInterface
{
    private $AccessKeyId;
    private $SecretAccessKey;
    private $endpoint = "dns.myhuaweicloud.com";
    private $error;
    private $domain;
    private $domainid;
    private HuaweiCloud $client;

    public function __construct($config)
    {
        $this->AccessKeyId = $config['AccessKeyId'];
        $this->SecretAccessKey = $config['SecretAccessKey'];
        $proxy = isset($config['proxy']) ? $config['proxy'] == 1 : false;
        $this->client = new HuaweiCloud($this->AccessKeyId, $this->SecretAccessKey, $this->endpoint, $proxy);
        $this->domain = $config['domain'];
        $this->domainid = $config['domainid'];
    }

    public function getError()
    {
        return $this->error;
    }

    public function check()
    {
        if ($this->getDomainList() != false) {
            return true;
        }
        return false;
    }

    //获取域名列表
    public function getDomainList($KeyWord = null, $PageNumber = 1, $PageSize = 20)
    {
        $offset = ($PageNumber - 1) * $PageSize;
        $query = ['offset' => $offset, 'limit' => $PageSize, 'name' => $KeyWord];
        $data = $this->send_request('GET', '/v2/zones', $query);
        if ($data) {
            $list = [];
            foreach ($data['zones'] as $row) {
                $list[] = [
                    'DomainId' => $row['id'],
                    'Domain' => rtrim($row['name'], '.'),
                    'RecordCount' => $row['record_num'],
                ];
            }
            return ['total' => $data['metadata']['total_count'], 'list' => $list];
        }
        return false;
    }

    //获取解析记录列表
    public function getDomainRecords($PageNumber = 1, $PageSize = 20, $KeyWord = null, $SubDomain = null, $Value = null, $Type = null, $Line = null, $Status = null, $SortField = null, $SortOrder = 'asc')
    {
        $offset = ($PageNumber - 1) * $PageSize;
        $query = ['type' => $Type, 'line_id' => $Line, 'name' => $KeyWord, 'offset' => $offset, 'limit' => $PageSize, 'records' => $Value];
        if (!isNullOrEmpty($Status)) {
            $Status = $Status == '1' ? 'ACTIVE' : 'DISABLE';
            $query['status'] = $Status;
        }
        if (!isNullOrEmpty($SubDomain)) {
            $SubDomain = $this->getHost($SubDomain);
            $query['name'] = $SubDomain;
            $query['search_mode'] = 'equal';
        }
        $allowedSort = ['Name' => 'name', 'Type' => 'type', 'UpdateTime' => 'updated_at'];
        if ($SortField && isset($allowedSort[$SortField])) {
            $query += [
                'sort_key' => $allowedSort[$SortField],
                'sort_dir' => strtolower($SortOrder),
            ];
        }
        $data = $this->send_request('GET', '/v2.1/zones/'.$this->domainid.'/recordsets', $query);
        if ($data) {
            $list = [];
            foreach ($data['recordsets'] as $row) {
                $name = substr($row['name'], 0, -(strlen($row['zone_name']) + 1));
                if ($name == '') $name = '@';
                $list[] = [
                    'RecordId' => $row['id'],
                    'Domain' => rtrim($row['zone_name'], '.'),
                    'Name' => $name,
                    'Type' => $row['type'],
                    'Value' => $row['records'],
                    'Line' => $row['line'],
                    'TTL' => $row['ttl'],
                    'MX' => isset($row['mx']) ? $row['mx'] : null,
                    'Status' => $row['status'] == 'ACTIVE' ? '1' : '0',
                    'Weight' => $row['weight'],
                    'Remark' => $row['description'],
                    'UpdateTime' => $row['updated_at'],
                ];
            }
            return ['total' => $data['metadata']['total_count'], 'list' => $list];
        }
        return false;
    }

    //获取子域名解析记录列表
    public function getSubDomainRecords($SubDomain, $PageNumber = 1, $PageSize = 20, $Type = null, $Line = null)
    {
        return $this->getDomainRecords($PageNumber, $PageSize, null, $SubDomain, null, $Type, $Line);
    }

    //获取解析记录详细信息
    public function getDomainRecordInfo($RecordId)
    {
        $data = $this->send_request('GET', '/v2.1/zones/'.$this->domainid.'/recordsets/'.$RecordId);
        if ($data) {
            $name = substr($data['name'], 0, -(strlen($data['zone_name']) + 1));
            if ($name == '') $name = '@';
            return [
                'RecordId' => $data['id'],
                'Domain' => rtrim($data['zone_name'], '.'),
                'Name' => $name,
                'Type' => $data['type'],
                'Value' => $data['records'],
                'Line' => $data['line'],
                'TTL' => $data['ttl'],
                'MX' => isset($data['mx']) ? $data['mx'] : null,
                'Status' => $data['status'] == 'ACTIVE' ? '1' : '0',
                'Weight' => $data['weight'],
                'Remark' => $data['description'],
                'UpdateTime' => $data['updated_at'],
            ];
        }
        return false;
    }

    //添加解析记录
    public function addDomainRecord($Name, $Type, $Value, $Line = '0', $TTL = 600, $MX = 1, $Weight = null, $Remark = null)
    {
        $rawName = $Name;
        $Name = $this->getHost($Name);
        if ($Type == 'TXT' && substr($Value, 0, 1) != '"') $Value = '"' . $Value . '"';
        $records = array_reverse(explode(',', $Value));
        $params = ['name' => $Name, 'type' => $this->convertType($Type), 'records' => $records, 'line' => $Line, 'ttl' => intval($TTL), 'description' => $Remark];
        if ($Weight > 0) $params['weight'] = intval($Weight);
        $data = $this->send_request('POST', '/v2.1/zones/'.$this->domainid.'/recordsets', null, $params);
        if (!$data && !empty($this->error)) {
            // 自动处理冲突与覆盖 / 幂等性：
            if ($this->isRecordConflictError($this->error)) {
                $existingRecords = $this->getSubDomainRecords($rawName, 1, 50);
                if ($existingRecords && !empty($existingRecords['list'])) {
                    // 1. 如果同线路已存在同类型、同值的记录，直接返回已有记录 ID（幂等成功，不报错）
                    foreach ($existingRecords['list'] as $rec) {
                        if ($rec['Type'] === $Type && $this->isSameLine($rec['Line'] ?? '', $Line) && $this->recordValuesMatch($rec['Value'], $records)) {
                            if ($this->isAcmeVerificationTxt($rawName, $Type, $Remark)) {
                                $this->cleanupOtherVerificationTxtRecords($existingRecords['list'], $rec['RecordId'], $Line);
                            }
                            $this->error = null;
                            return $rec['RecordId'];
                        }
                    }
                    // 2. 存在冲突记录（如添加 CNAME 时已有 TXT，或已有不同值的记录），仅清理同线路冲突后重试
                    $deletedAny = false;
                    foreach ($existingRecords['list'] as $conflict) {
                        if (!$this->isSameLine($conflict['Line'] ?? '', $Line)) {
                            continue;
                        }
                        if ($Type === 'CNAME' || $conflict['Type'] === $Type || $conflict['Type'] === 'CNAME') {
                            $this->deleteDomainRecord($conflict['RecordId']);
                            $deletedAny = true;
                        }
                    }
                    if ($deletedAny) {
                        $this->error = null;
                        $data = $this->send_request('POST', '/v2.1/zones/'.$this->domainid.'/recordsets', null, $params);
                    }
                }
            }
        }
        if (is_array($data)) {
            // 华为云同主机同线路多个 TXT 记录会变成加权轮询，覆盖旧的证书验证 TXT 可避免多视角验证(MPIC)失败
            if ($Type === 'TXT' && $Remark === 'Cloudflare 证书验证' && $this->isAcmeVerificationTxt($rawName, $Type, $Remark)) {
                $existingRecords = $this->getSubDomainRecords($rawName, 1, 50);
                if ($existingRecords && !empty($existingRecords['list'])) {
                    $this->cleanupOtherVerificationTxtRecords($existingRecords['list'], $data['id'], $Line);
                }
            }
            return $data['id'];
        }
        return false;
    }

    /**
     * 判断华为云返回的错误是否为记录冲突或重复记录集错误
     */
    private function isRecordConflictError($error)
    {
        if (empty($error)) {
            return false;
        }
        foreach (['already exists', 'Conflicts with Record Set', 'Duplicate recordset', 'duplicate', 'conflict'] as $needle) {
            if (stripos($error, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断两条记录是否属于同一解析线路（兼容 default_view / 0 / default）
     */
    private function isSameLine($recLine, $targetLine)
    {
        $defaults = ['', '0', 'default', 'default_view'];
        if (in_array((string)$targetLine, $defaults, true)) {
            return in_array((string)$recLine, $defaults, true);
        }
        return (string)$recLine === (string)$targetLine;
    }

    /**
     * 规范化解析记录值以便做幂等对比
     */
    private function normalizeRecordValues($val)
    {
        $items = is_array($val) ? $val : explode(',', (string)$val);
        $normalized = [];
        foreach ($items as $item) {
            $norm = rtrim(trim(trim((string)$item), '"'), '.');
            if ($norm !== '') {
                $normalized[] = $norm;
            }
        }
        sort($normalized);
        return $normalized;
    }

    /**
     * 判断已有记录值与目标记录值是否等价
     */
    private function recordValuesMatch($existingValue, array $targetRecords)
    {
        $existing = $this->normalizeRecordValues($existingValue);
        $target = $this->normalizeRecordValues($targetRecords);
        if (empty($existing) || empty($target)) {
            return false;
        }
        if ($existing === $target) {
            return true;
        }
        return count($target) === 1 && in_array($target[0], $existing, true);
    }

    /**
     * 判断是否为 ACME / Cloudflare 证书验证类 TXT 记录
     */
    private function isAcmeVerificationTxt($rawName, $type, $remark)
    {
        if ($type !== 'TXT') {
            return false;
        }
        if ($remark === 'Cloudflare 证书验证') {
            return true;
        }
        $lower = strtolower(rtrim((string)$rawName, '.'));
        return $lower === '_acme-challenge' || str_starts_with($lower, '_acme-challenge.');
    }

    /**
     * 清理同线路下除当前生效记录之外的其他旧验证 TXT 记录集
     */
    private function cleanupOtherVerificationTxtRecords(array $records, $keepRecordId, $targetLine)
    {
        foreach ($records as $rec) {
            if (($rec['Type'] ?? '') !== 'TXT') {
                continue;
            }
            if (($rec['RecordId'] ?? '') === $keepRecordId) {
                continue;
            }
            if (!$this->isSameLine($rec['Line'] ?? '', $targetLine)) {
                continue;
            }
            $this->deleteDomainRecord($rec['RecordId']);
        }
    }

    //修改解析记录
    public function updateDomainRecord($RecordId, $Name, $Type, $Value, $Line = '0', $TTL = 600, $MX = 1, $Weight = null, $Remark = null)
    {
        $Name = $this->getHost($Name);
        if ($Type == 'TXT' && substr($Value, 0, 1) != '"') $Value = '"' . $Value . '"';
        $records = array_reverse(explode(',', $Value));
        $params = ['name' => $Name, 'type' => $this->convertType($Type), 'records' => $records, 'line' => $Line, 'ttl' => intval($TTL), 'description' => $Remark];
        if ($Weight > 0) $params['weight'] = intval($Weight);
        $data = $this->send_request('PUT', '/v2.1/zones/'.$this->domainid.'/recordsets/'.$RecordId, null, $params);
        return is_array($data);
    }

    //修改解析记录备注
    public function updateDomainRecordRemark($RecordId, $Remark)
    {
        return false;
    }

    //删除解析记录
    public function deleteDomainRecord($RecordId)
    {
        $data = $this->send_request('DELETE', '/v2.1/zones/'.$this->domainid.'/recordsets/'.$RecordId);
        return is_array($data);
    }

    //设置解析记录状态
    public function setDomainRecordStatus($RecordId, $Status)
    {
        $Status = $Status == '1' ? 'ENABLE' : 'DISABLE';
        $params = ['status' => $Status];
        $data = $this->send_request('PUT', '/v2.1/recordsets/'.$RecordId.'/statuses/set', null, $params);
        return is_array($data);
    }

    //获取解析记录操作日志
    public function getDomainRecordLog($PageNumber = 1, $PageSize = 20, $KeyWord = null, $StartDate = null, $endDate = null)
    {
        return false;
    }

    //获取解析线路列表
    public function getRecordLine()
    {
        $file_path = app()->getBasePath().'data'.DIRECTORY_SEPARATOR.'huawei_line.json';
        $content = file_get_contents($file_path);
        $data = json_decode($content, true);
        if ($data) {
            return $data;
            $list = [$data['DEFAULT']['id'] => ['name' => $data['DEFAULT']['zh'], 'parent' => null]];
            $this->processLineList($list, $data['ISP'], null, 1, 1);
            $this->processLineList($list, $data['REGION'], null, null, 1);
            //file_put_contents($file_path, json_encode($list, JSON_UNESCAPED_UNICODE));
            return $list;
        }
        return false;
    }

    private function processLineList(&$list, $line_list, $parent, $rootId = null, $rootName = null)
    {
        foreach ($line_list as $row) {
            if ($rootId && $rootId !== 1) {
                $row['id'] = $rootId.'_'.$row['id'];
            }
            if ($rootName && $rootName !== 1) {
                $row['zh'] = $rootName.'_'.$row['zh'];
            }
            $list[$row['id']] = ['name' => $row['zh'], 'parent' => $parent];
            if (isset($row['children']) && !empty($row['children'])) {
                $this->processLineList($list, $row['children'], $row['id'], $rootId === 1 ? $row['id'] : $rootId, $rootName === 1 ? $row['zh'] : $rootName);
            }
        }
    }

    //获取域名概览信息
    public function getDomainInfo()
    {
        return $this->send_request('GET', '/v2/zones/'.$this->domainid);
    }

    //获取域名最低TTL
    public function getMinTTL()
    {
        return false;
    }

    public function addDomain($Domain)
    {
        $params = [
            'name' => $Domain,
        ];
        $data = $this->send_request('POST', '/v2/zones', null, $params);
        if ($data) {
            return ['id' => $data['id'], 'name' => rtrim($data['name'], '.')];
        }
        return false;
    }

    private function convertType($type)
    {
        return $type;
    }

    private function getHost($Name)
    {
        if ($Name == '@') $Name = '';
        else $Name .= '.';
        $Name .= $this->domain . '.';
        return $Name;
    }

    private function send_request($method, $path, $query = null, $params = null)
    {
        try{
            return $this->client->request($method, $path, $query, $params);
        }catch(Exception $e){
            $this->setError($e->getMessage());
            return false;
        }
    }

    private function setError($message)
    {
        $this->error = $message;
        //file_put_contents('logs.txt',date('H:i:s').' '.$message."\r\n", FILE_APPEND);
    }
}
