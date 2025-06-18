## 1. Syslog to Sentinel pipeline

Go to the `Microsoft Sentinel Syslog` pack and copy the `sentinel_syslog` pipeline

![image](https://github.com/user-attachments/assets/aacd5bc8-89e4-4514-b8e5-8ab4bbca5f7e)

Paste the pipeline

![image](https://github.com/user-attachments/assets/9b66fd2f-55bb-4b47-beef-62416c2d2c8c)

![image](https://github.com/user-attachments/assets/e10cfdc6-6511-43c2-8177-7ed8b3d5ded0)

Edit the `Eval` step of the pipeline:
- Change `String(facility) || facilityName` to `facilityName` for the `Facility` field
  - Sentinel accepts `facilityName` (name) but not `facility` (number) for the `Facility` column
- Add field for `SourceSystem`: `'Cribl'`
- Add `SourceSystem` under `Keep fields`

![image](https://github.com/user-attachments/assets/76323605-88e5-43c8-aa07-a0d4b9a79327)

## 2. WEF to Sentinel pipeline

Go to the `Microsoft Sentinel` pack and copy the `wef_security_events` pipeline

![image](https://github.com/user-attachments/assets/a3dab855-829d-43fa-8965-e29e840bd234)

Paste the pipeline

![image](https://github.com/user-attachments/assets/9b66fd2f-55bb-4b47-beef-62416c2d2c8c)

![image](https://github.com/user-attachments/assets/0ca09d60-4a05-4571-a296-bbd12e907907)

### 2.1. Including `EventData` field

#### 2.1.1. `EventData` field for AMA-ingested event

AMA conditionally enriches the `EventData` field depending on the type of event

Logon failure event (`4625`) does not have `EventData` field populated:

![image](https://github.com/user-attachments/assets/7be6f589-d838-4ee0-99ab-8c9189bd0ad3)

While privileged service event (`4673`) has the `EventData` field as XML, and LAW displays it as a multi-line XML:

![image](https://github.com/user-attachments/assets/a78b9881-f551-4068-8162-7f17d12436fa)

#### 2.1.2. Keeping `EventData` in Cribl

A XML or JSON copy of the `EventData` can be contained in the `EventData` field by enabling step 2 or step 6 of the pipeline

![image](https://github.com/user-attachments/assets/a3bd3978-e30a-4e1e-bfcf-1236911c6a15)

This affects how Sentinel receives the event

##### XML:

The original JS checks for `<UserData>` and uses `<UserData>` if it exists, otherwise uses `<EventData>`

```js
_raw.indexOf("<UserData>") > -1 ?
  _raw.substring(_raw.indexOf("<UserData>"),_raw.indexOf("</UserData>") + "</UserData>".length) :
  _raw.substring(_raw.indexOf("<EventData>"),_raw.indexOf("</EventData>") + "</EventData>".length)
```

This sends the `EventData` XML as a single line string to Sentinel:

![image](https://github.com/user-attachments/assets/3c567c7e-fbbd-42d7-b64c-0a9dc9dafbdf)

To capture just `<EventData>` and format it into a multi-line XML, replace the expression to the following:

```js
_raw.indexOf("<EventData>") > -1 ? _raw.substring(_raw.indexOf("<EventData>"),_raw.indexOf("</EventData>") + "</EventData>".length).replace(/Data>/g,"Data>\n") : null
```

![image](https://github.com/user-attachments/assets/afcbacae-847a-439e-aef4-f760c9aaab36)

##### JSON:

This sends the `_raw.Event.EventData.Data` array to Sentinel:

![image](https://github.com/user-attachments/assets/24061221-278b-445a-b4ba-c1270c2ba1a8)

### 2.2. Adding logon type name to the event

A Windows security event ingested directly by AMA is enriched with the logon type name according to the logon type numeric, this can be done in Cribl via the `Lookup` function

The logon type name lookup table: https://github.com/joetanx/cribl/blob/main/windows_logon_type.csv

Upload the csv to Knowledge → Lookups:

![image](https://github.com/user-attachments/assets/39af7a6f-8b4c-424f-aca9-50a86e121aa8)

![image](https://github.com/user-attachments/assets/b59bf094-6558-49c2-9782-f080ad869256)

Add a lookup step to the pipeline:

![image](https://github.com/user-attachments/assets/b10a290a-7624-4264-b86e-fd91193352b1)

Lookup file path: `windows_logon_type.csv`

Lookup fields:

|Lookup Field Name in Event|Corresponding Field Name in Lookup|
|---|---|
|`LogonType`|`LogonType`|

|Output Field Name from Lookup|Lookup Field Name in Event|
|---|---|
|`LogonTypeName`|`LogonTypeName`|

![image](https://github.com/user-attachments/assets/46499d89-8a12-4c73-9a7e-f39154d54c7c)

### 2.3. Adding event message to the event

A Windows security event ingested directly by AMA is enriched with the event message according to the event ID

This can also be done in Cribl via the `Lookup` function, but need a bit more transformation to get the format correct

#### 2.3.1. Looking up event message template with event ID and provider name

Event message lookup table: https://github.com/joetanx/cribl/blob/main/windows_event_id.csv

Upload the csv to Knowledge → Lookups:

![image](https://github.com/user-attachments/assets/39af7a6f-8b4c-424f-aca9-50a86e121aa8)

![image](https://github.com/user-attachments/assets/0dc8b035-d19d-45bb-96fb-dec779c84a5e)

Add a lookup step to the pipeline:

![image](https://github.com/user-attachments/assets/b10a290a-7624-4264-b86e-fd91193352b1)

Lookup file path: `windows_event_id.csv`

Lookup fields:

|Lookup Field Name in Event|Corresponding Field Name in Lookup|
|---|---|
|`EventID`|`event_code`|
|`EventSourceName`|`provider`|

|Output Field Name from Lookup|Lookup Field Name in Event|
|---|---|
|`template`|`__message`|
|`fields`|`__fields`|

This lookup function:
- selects the row with the event ID and provider combination (because different providers can happen to use the same event ID)
- returns the template and fields column
  - template: the message template, may contain `%1`, `%2`, etc placeholders for the specified fields depending on the event
  - fields: the fields to reference for each `%1`, `%2`, etc placeholders

![image](https://github.com/user-attachments/assets/21b4bd60-3986-4c9d-afad-94ccf7dd5240)

#### 2.3.2. Fill in event data to the message template placeholders

A message template can contain 0 to N placeholders, this would need to have a loop or loopback function to map the fields to placeholders

The code function is required to perform this:
1. `__e.__fields.split(',')` converts the field names into an array
2. `.reduce((msg, field, index) => ...)` iterates through the array, applying transformations to `__e.__message`
3. `msg.replace(`%${index + 1}`, __e[field])` peplaces placeholders (`%1`, `%2`, etc.) in the message with corresponding values from `__e`

```js
__e.__message = __e.__fields.split(',').reduce((msg, field, index) => msg.replace(`%${index + 1}`, __e[field]), __e.__message)
```

> [!Tip]
>
> The special variable `__e` represents the `(context)` event inside a JavaScript expression.
> - Using `__e` with _square bracket notation_, can access any field within the event object (e.g. `__e['hostname']`)
> - In most cases, using `__e['field']` and `__e.field` are the same, but this notation **must be used** for fields that contain a special (non-alphanumeric) character like `user-agent`, `kubernetes.namespace_name`, or `@timestamp`
> 
> The special variable `__e` is useful in this case , consider below example event:
> 
> ```
> {
>   "EventID": 145,
>   "Channel": "Microsoft-Windows-WinRM/Operational",
>   "Computer": "DC.lab.vx",
>   "Security_UserID": "S-1-5-20",
>   "__message": "WSMan operation %1 started with resourceUri %2",
>   "__fields": "operationName,resourceUri",
>   "operationName": "Enumeration",
>   "resourceUri": "http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription",
>   "EventSourceName": "Microsoft-Windows-WinRM",
>   "Type": "SecurityEvent"
> }
> ```
>
> This JS produces `WSMan operation operationName started with resourceUri resourceUri`
> 
> ```js
>__message.replace('%1',__fields.split(',')[0]).replace('%2',__fields.split(',')[1])
> ```
>
> While this JS using `__e` produces `WSMan operation Enumeration started with resourceUri http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription`
> 
> ```js
> __message.replace('%1',__e[__fields.split(',')[0]]).replace('%2',__e[__fields.split(',')[1]])
> ```

![image](https://github.com/user-attachments/assets/a1ce694d-ecaa-475f-9748-22e6050dba1c)

#### 2.3.3. Trim message and concatenate to event ID

Several of the message templates are multi-line, the first line would be sufficient to enrich the event with activity information

`Eval` can be used to:
- Keep only the first line by checking for `\r\r\n` and then using `substring()` to trim `__message`
- Appending `EventID` with `__message` can be done via template literal or string concatenation

Template literal:

```js
`${EventID} - ${__message.indexOf('\\r\\r\\n') > -1 ? __message.substring(0,__message.indexOf('\\r\\r\\n')) : __message.substring(0,__message.length)}`
```

String concatenation:

```js
EventID + ' - ' + (__message.indexOf('\\r\\r\\n') > -1 ? __message.substring(0,__message.indexOf('\\r\\r\\n')) : __message.substring(0,__message.length))
```

![image](https://github.com/user-attachments/assets/1bfffd61-169a-4b03-aada-a18625f081a6)

### 2.4. Adding accounts-related information to the event

|Name|Value expression|
|---|---|
|SubjectAccount|`SubjectDomainName && SubjectUserName ? SubjectDomainName + '\\' + SubjectUserName : null`|
|TargetAccount|`TargetDomainName && TargetUserName ? TargetDomainName + '\\' + TargetUserName : null`|
|Account|`TargetAccount \|\| SubjectAccount ? (TargetAccount ? TargetAccount : SubjectAccount) : null`|
|AccountType|`Account ? (/NT Service\|NT AUTHORITY\|\$/.test(Account) ? 'Machine' : 'User') : null`|

![image](https://github.com/user-attachments/assets/93fc60a3-b9e4-46c7-a0b6-12a9d7445d45)

### 2.5. Capture `EventID__value` field

Some events like `Windows PowerShell` has EventID field as such:

```xml
<EventID Qualifiers="0">403</EventID>
```

The XML parsing places this into `EventID_Qualifiers` and `EventID__value` fields

Add rename of `EventID__value` to `EventID` to send it correctly:

![image](https://github.com/user-attachments/assets/97791bbf-05b5-46e6-bf48-b35401d8564b)

### 2.6. Drop unused `ThreadID`, `ProcessID` and `EventID_Qualifiers` fields

Edit the existing eval function to drop `ThreadID`, `ProcessID` and `EventID_Qualifiers`

![image](https://github.com/user-attachments/assets/b276cfe7-c580-4f46-86ee-dded61f3c068)
