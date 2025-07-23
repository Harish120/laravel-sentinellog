<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class() extends Migration
{
    public function up(): void
    {
        Schema::create(config('sentinel-log.table_name', 'authentication_logs'), function (Blueprint $table) {
            $table->id();
            $table->string('authenticatable_type')->nullable();
            $table->unsignedBigInteger('authenticatable_id')->nullable();
            $table->string('session_id')->nullable();
            $table->string('event_name');
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('device_info')->nullable();
            $table->json('location')->nullable();
            $table->boolean('is_successful')->default(false);
            $table->timestamp('event_at')->useCurrent();
            $table->timestamp('cleared_at')->nullable();
            $table->timestamps();

            $table->index(['authenticatable_type', 'authenticatable_id'], config('sentinel-log.table_name', 'authentication_logs').'_auth_type_auth_id_idx');
            $table->index('event_name');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('sentinel-log.table_name', 'authentication_logs'));
    }
};
