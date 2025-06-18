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

##### `EventData` field for AMA-ingested event

AMA conditionally enriches the `EventData` field depending on the type of event

Logon failure event (`4625`) does not have `EventData` field populated:

![image](https://github.com/user-attachments/assets/7be6f589-d838-4ee0-99ab-8c9189bd0ad3)

While privileged service event (`4673`) has the `EventData` field as XML, and LAW displays it as a multi-line XML:

![image](https://github.com/user-attachments/assets/a78b9881-f551-4068-8162-7f17d12436fa)

##### Keeping `EventData` in Cribl

A XML or JSON copy of the `EventData` can be contained in the `EventData` field by enabling step 2 or step 6 of the pipeline

![image](https://github.com/user-attachments/assets/e58ace4e-d85c-4035-a17e-b2ae7ad3061d)

The affects how Sentinel receives the event

**XML**:

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
_raw.indexOf("<EventData>") > -1 ? _raw.substring(_raw.indexOf("<EventData>"),_raw.indexOf("</EventData>") + "</EventData>".length).replace(/Data>/g,"Data>\n") : ''
```

**JSON**:

This sends the `_raw.Event.EventData.Data` array to Sentinel:

![image](https://github.com/user-attachments/assets/24061221-278b-445a-b4ba-c1270c2ba1a8)

### 2.2. Enriching wef events

A Windows security event ingested directly via AMA enriches the event with `Activity` and `LogonTypeName` fields, this can be done in Cribl via the `Lookup` function

The lookup tables for:
- Event messages according to the [common security events collected by sentinel](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference) is available [here](/windows_security_events.csv)
- [Logon types](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events) is available [here](/windows_logon_type.csv)

Upload the csv to Knowledge → Lookups:

![image](https://github.com/user-attachments/assets/148b8482-0c91-41f6-b9a6-8dc15c2cd98a)


![image](https://github.com/user-attachments/assets/b2c08eac-eec0-4779-936b-2b3d9863b0f9)

![image](https://github.com/user-attachments/assets/0ebbdd93-e6b5-4e02-abaa-31868ba32e1e)

Add a lookup step to the pipeline for each `Activity` and `LogonTypeName` lookups:

![image](https://github.com/user-attachments/assets/0c006dc6-c0d4-4cf8-94b9-7a10a0564c43)

Place the lookup steps before the clean up step and configure the following:

|Lookup file path|Lookup fields|Output fields|
|---|---|---|
|`windows_security_events.csv`|Lookup Field Name in Event: `EventID`<br>Corresponding Field Name in Lookup: `EventID`|Output Field Name from Lookup: `Activity`<br>Lookup Field Name in Event: `Activity`|
|`windows_logon_type.csv`|Lookup Field Name in Event: `LogonType`<br>Corresponding Field Name in Lookup: `LogonType`|Output Field Name from Lookup: `LogonTypeName`<br>Lookup Field Name in Event: `LogonTypeName`|

![image](https://github.com/user-attachments/assets/4c4e58c9-85ae-4c9a-9fd2-572810000c6d)

![image](https://github.com/user-attachments/assets/65b0d6f4-ca1c-4dd9-8ddd-e48997dcffaa)

The `Activity` and `LogonTypeName` columns in Sentinel gets populated according to the lookups:

![image](https://github.com/user-attachments/assets/40151074-64da-4d8b-97fe-b76472ccc71a)

### 2.3. Capture `EventID__value` field

Some events like `Windows PowerShell` has EventID field as such:

```xml
<EventID Qualifiers="0">403</EventID>
```

The XML parsing places this into `EventID_Qualifiers` and `EventID__value` fields

Add rename of `EventID__value` to `EventID` to send it correctly:

![image](https://github.com/user-attachments/assets/97791bbf-05b5-46e6-bf48-b35401d8564b)

### 2.4. Drop unused `ThreadID`, `ProcessID` and `EventID_Qualifiers` fields

Edit the existing eval function to drop `ThreadID`, `ProcessID` and `EventID_Qualifiers`

![image](https://github.com/user-attachments/assets/b276cfe7-c580-4f46-86ee-dded61f3c068)
