<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sentinel_sessions', function (Blueprint $table) {
            $table->id();
            $table->morphs('authenticatable');
            $table->string('session_id')->unique();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->json('device_info')->nullable();
            $table->json('location')->nullable();
            $table->timestamp('last_activity')->useCurrent();
            $table->timestamps();
            $table->index(['authenticatable_type', 'authenticatable_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sentinel_sessions');
    }
};