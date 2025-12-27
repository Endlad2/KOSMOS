# KOSMOS Coding Style Guide

## 📋 Общие принципы

### Читаемость и понятность
- **Код должен быть понятен новым разработчикам** через 6 месяцев после написания
- **Имена переменных и функций должны быть самодокументирующими**
- **Избегайте "умного" кода** в пользу понятного и поддерживаемого
- **Комментарии должны объяснять "почему", а не "что"**

### Стабильность и надежность
- **Каждая функция должна проверять свои входные параметры**
- **Обработка ошибок обязательна** для всех критических операций
- **Избегайте утечек ресурсов** (память, дескрипторы файлов, мьютексы)
- **Все публичные API должны быть документированы**

## 🏗️ Архитектурные рекомендации

### 1. Организация кода
```
// ПЛОХО: Все в одном файле
// file: kernel.c
void init_kernel() { ... }
void handle_interrupt() { ... }
void manage_memory() { ... }

// ХОРОШО: Разделение на модули
// file: kernel/init.c
void kernel_init() { ... }

// file: kernel/interrupts.c  
void interrupt_handler() { ... }

// file: mm/paging.c
void setup_paging() { ... }
```

### 2. Занесение повторяющихся действий в функции
```c
// ПЛОХО: Повторяющийся код
void process_user_input() {
    // ... 50 строк кода ...
    if (validate_buffer(buffer1, size1)) {
        // обработка
    }
    // ... еще 50 строк ...
    if (validate_buffer(buffer2, size2)) {
        // другая обработка
    }
}

// ХОРОШО: Вынесение в функцию
static BOOL validate_input_buffer(PVOID buffer, SIZE_T size) {
    if (!buffer || size == 0) {
        KOSMOS_LOG_ERROR("Invalid buffer parameters");
        return FALSE;
    }
    if (size > MAX_BUFFER_SIZE) {
        KOSMOS_LOG_WARNING("Buffer size exceeds maximum");
        return FALSE;
    }
    return TRUE;
}

void process_user_input() {
    if (!validate_input_buffer(buffer1, size1)) return;
    if (!validate_input_buffer(buffer2, size2)) return;
    // ... основная логика ...
}
```

### 3. Разделение объявлений и реализаций
```
// ПЛОХАЯ СТРУКТУРА:
// file: driver.c
typedef struct _DEVICE_EXTENSION {
    // поля структуры
} DEVICE_EXTENSION;

NTSTATUS driver_entry(...) {
    // реализация
}

void helper_function(...) {
    // реализация
}

// ХОРОШАЯ СТРУКТУРА:
// file: include/drivers/device.h
#pragma once

typedef struct _DEVICE_EXTENSION {
    // объявление структуры
} DEVICE_EXTENSION;

NTSTATUS driver_entry(...);
void helper_function(...);

// file: drivers/device/device.c
#include "device.h"

NTSTATUS driver_entry(...) {
    // реализация
}

// file: drivers/device/helpers.c  
#include "device.h"

void helper_function(...) {
    // реализация
}
```

## 📁 Организация заголовочных файлов

### 1. Правила для `.h` файлов
```c
// file: include/kosmos/mm/pool.h

// 1. Защита от повторного включения
#ifndef _KOSMOS_MM_POOL_H
#define _KOSMOS_MM_POOL_H

// 2. Только необходимые инклюды
#include <kosmos/types.h>
#include <kosmos/status.h>

// 3. Только объявления, НЕ определения
typedef struct _POOL_DESCRIPTOR {
    PVOID BaseAddress;
    SIZE_T Size;
    ULONG Flags;
} POOL_DESCRIPTOR, *PPOOL_DESCRIPTOR;

// 4. Документация Doxygen-style
/**
 * @brief Инициализирует пул памяти
 * @param Pool Указатель на дескриптор пула
 * @param Size Размер пула в байтах
 * @param Flags Флаги инициализации
 * @return STATUS_SUCCESS при успехе, код ошибки при неудаче
 */
NTSTATUS 
KOSMOS_API
PoolInitialize(
    _Out_ PPOOL_DESCRIPTOR Pool,
    _In_ SIZE_T Size,
    _In_ ULONG Flags
);

/**
 * @brief Выделяет память из пула
 * @param Pool Дескриптор пула
 * @param Size Запрашиваемый размер
 * @return Указатель на память или NULL при ошибке
 */
PVOID
KOSMOS_API
PoolAllocate(
    _In_ PPOOL_DESCRIPTOR Pool,
    _In_ SIZE_T Size
);

// 5. Завершающая директива
#endif // _KOSMOS_MM_POOL_H
```

### 2. Правила для `.c` файлов
```c
// file: mm/pool.c

// 1. Инклюд своего заголовка первым
#include "pool.h"

// 2. Системные инклюды
#include <ntdef.h>
#include <rtl.h>

// 3. Локальные инклюды
#include "pool_internal.h"
#include "../debug/log.h"

// 4. Статические функции (только для этого файла)
static VOID
PoolValidateDescriptor(
    _In_ PPOOL_DESCRIPTOR Pool
    )
{
    ASSERT(Pool != NULL);
    ASSERT(Pool->BaseAddress != NULL);
    ASSERT(Pool->Size > 0);
}

// 5. Реализация экспортируемых функций
NTSTATUS
PoolInitialize(
    _Out_ PPOOL_DESCRIPTOR Pool,
    _In_ SIZE_T Size,
    _In_ ULONG Flags
    )
{
    NTSTATUS status;
    
    // Проверка параметров
    if (!Pool || Size == 0) {
        KOSMOS_LOG_ERROR("Invalid parameters to PoolInitialize");
        return STATUS_INVALID_PARAMETER;
    }
    
    // Инициализация
    RtlZeroMemory(Pool, sizeof(POOL_DESCRIPTOR));
    
    Pool->BaseAddress = ExAllocatePoolWithTag(NonPagedPool, Size, 'looP');
    if (!Pool->BaseAddress) {
        KOSMOS_LOG_ERROR("Failed to allocate pool memory");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Pool->Size = Size;
    Pool->Flags = Flags;
    
    KOSMOS_LOG_INFO("Pool initialized: 0x%p, size: %lu", 
                   Pool->BaseAddress, Size);
    
    return STATUS_SUCCESS;
}
```

## 📝 Соглашения об именовании

### 1. Префиксы
```c
// Типы
typedef struct _KOSMOS_THREAD { ... } KOSMOS_THREAD, *PKOSMOS_THREAD;
typedef enum _KOSMOS_STATUS { ... } KOSMOS_STATUS;

// Функции
KOSMOS_API NTSTATUS ThreadCreate(...);  // Модуль Thread
KOSMOS_API NTSTATUS MemoryAllocate(...); // Модуль Memory

// Константы
#define KOSMOS_MAX_THREADS     256
#define KOSMOS_PAGE_SIZE       4096

// Макросы
#define KOSMOS_ASSERT(expr)    ASSERT(expr)
#define KOSMOS_ALIGN(size, align) (((size) + (align) - 1) & ~((align) - 1))
```

### 2. Венгерская нотация (опционально, но рекомендуется)
```c
// Префиксы типов:
// p - pointer (указатель)
// h - handle (дескриптор)
// dw - DWORD (32-битное)
// ul - ULONG
// sz - zero-terminated string

PKOSMOS_THREAD pThread;      // Указатель на поток
HANDLE hFile;                // Дескриптор файла
DWORD dwErrorCode;          // Код ошибки
ULONG ulThreadId;           // ID потока
PWSTR szFileName;           // Имя файла
```

## 🔧 Практические рекомендации

### 1. Длина функций
```c
// ПЛОХО: Функция на 200+ строк
NTSTATUS DoEverything(...) {
    // ... 200 строк кода ...
}

// ХОРОШО: Разделение на логические блоки
NTSTATUS ProcessRequest(...) {
    NTSTATUS status;
    
    status = ValidateRequest(...);
    if (!NT_SUCCESS(status)) return status;
    
    status = PrepareResources(...);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    status = ExecuteOperation(...);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    status = SaveResults(...);
    
cleanup:
    CleanupResources(...);
    return status;
}
```

### 2. Обработка ошибок
```c
// ПЛОХО: Игнорирование ошибок
HANDLE hFile = CreateFile(...);
WriteFile(hFile, ...);
CloseHandle(hFile);

// ХОРОШО: Полная обработка ошибок
NTSTATUS WriteToFile(PCWSTR filename, PVOID data, SIZE_T size) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten;
    NTSTATUS status = STATUS_SUCCESS;
    
    hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        status = STATUS_ACCESS_DENIED;
        KOSMOS_LOG_ERROR("Failed to create file: %ws", filename);
        goto cleanup;
    }
    
    if (!WriteFile(hFile, data, size, &bytesWritten, NULL)) {
        status = STATUS_WRITE_FAULT;
        KOSMOS_LOG_ERROR("Write failed: %lu", GetLastError());
        goto cleanup;
    }
    
    if (bytesWritten != size) {
        status = STATUS_PARTIAL_COPY;
        KOSMOS_LOG_WARNING("Partial write: %lu of %lu bytes", 
                          bytesWritten, size);
    }
    
cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    
    return status;
}
```

### 3. Максимальная длина строк
- **80 символов** для кода (для удобного сравнения в diff)
- **120 символов** для комментариев
- Используйте обратный слеш для переноса длинных строк

```c
// ХОРОШО:
status = SomeVeryLongFunctionName(
    parameter1, 
    parameter2,
    parameter3,
    parameter4
    );

// ПЛОХО:
status = SomeVeryLongFunctionName(parameter1, parameter2, parameter3, parameter4, parameter5, parameter6);
```

## 📊 Пример правильной структуры проекта

```
kosmos/
├── include/                   # Публичные заголовки
│   ├── kosmos/
│   │   ├── kernel.h          # Основное API ядра
│   │   ├── mm/               # Менеджер памяти
│   │   │   ├── pool.h
│   │   │   └── heap.h
│   │   ├── drivers/          # Драйверы
│   │   │   └── pci.h
│   │   └── utils/            # Утилиты
│   │       └── string.h
│   └── internal/             # Внутренние заголовки
│       └── debug.h
├── kernel/                   # Исходники ядра
│   ├── init.c
│   ├── thread.c
│   ├── sync.c
│   └── include/             # Приватные заголовки модуля
│       └── thread_private.h
├── mm/                       # Менеджер памяти
│   ├── pool.c
│   ├── heap.c
│   └── paging.c
├── drivers/                  # Драйверы
│   ├── pci/
│   │   ├── pci.c
│   │   └── pci_private.h
│   └── storage/
│       ├── ata.c
│       └── include/
│           └── ata_io.h
└── utils/                    # Утилиты
    ├── string.c
    └── debug.c
```

## 🚨 Запрещенные практики

### 1. Никогда не делайте так:
```c
// Магические числа
for (int i = 0; i < 256; i++) { ... }  // ПЛОХО!

// Вместо этого:
#define MAX_THREADS 256
for (int i = 0; i < MAX_THREADS; i++) { ... }

// Глобальные переменные в заголовках
extern int g_globalCounter;  // ПЛОХО!

// Функции без проверки параметров
void dangerous_function(void* ptr) {
    *((int*)ptr) = 42;  // СЕГФАУЛТ если ptr == NULL
}

// Утечки в макросах
#define SQUARE(x) x * x  // ПЛОХО: SQUARE(a + b) -> a + b * a + b
#define SQUARE(x) ((x) * (x))  // ХОРОШО
```

## 📚 Дополнительные рекомендации

### 1. Для C++ кода (если будет использоваться)
```cpp
// file: include/kosmos/utils/smart_ptr.hpp
#pragma once

namespace kosmos {
namespace utils {

template<typename T>
class UniquePtr {
public:
    explicit UniquePtr(T* ptr = nullptr) : ptr_(ptr) {}
    ~UniquePtr() { reset(); }
    
    // Запрет копирования
    UniquePtr(const UniquePtr&) = delete;
    UniquePtr& operator=(const UniquePtr&) = delete;
    
    // Разрешение перемещения
    UniquePtr(UniquePtr&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    
    void reset(T* ptr = nullptr) {
        delete ptr_;
        ptr_ = ptr;
    }
    
private:
    T* ptr_;
};

} // namespace utils
} // namespace kosmos
```

### 2. Комментарии в стиле Doxygen
```c
/**
 * @brief Краткое описание функции
 * @detailed Подробное описание, можно на несколько строк
 * 
 * @param param1 Описание первого параметра
 * @param param2 Описание второго параметра
 * @param[out] output Параметр, используемый для вывода
 * 
 * @return Код возврата или результат
 * @retval STATUS_SUCCESS Успешное выполнение
 * @retval STATUS_INVALID_PARAMETER Некорректные параметры
 * 
 * @note Важное примечание для разработчиков
 * @warning Предупреждение о возможных проблемах
 * @bug Известные баги или ограничения
 * 
 * @example
 * NTSTATUS status = ExampleFunction(param1, param2, &output);
 * if (NT_SUCCESS(status)) {
 *     // Обработка результата
 * }
 */
```

## 🔍 Проверка кода

### 1. Перед коммитом:
```bash

# Статический анализ
clang-tidy --checks=* source_file.c

# Построение и тесты
cmake --build build --target kosmos-tests
```

### 2. Чек-лист ревью кода:
- [ ] Соответствует стилю KOSMOS
- [ ] Нет дублирования кода
- [ ] Проверка всех параметров функций
- [ ] Обработка всех возможных ошибок
- [ ] Документация публичных API
- [ ] Тесты для новой функциональности
- [ ] Сохранение обратной совместимости (если нужно)

---

**Помните:** Хороший код — это код, который легко читать, понимать и поддерживать. Следуя этим правилам, мы создадим стабильную и надежную операционную систему KOSMOS, которую будет приятно разрабатывать годами.
